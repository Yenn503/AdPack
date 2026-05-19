package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

// ValidationResult tracks validation across multiple protocols
type ValidationResult struct {
	Credential core.Credential
	SMB        ValidationCheck
	LDAP       ValidationCheck
	WinRM      ValidationCheck
	RDP        ValidationCheck
	IsAdmin    bool
	Hosts      []string // Hosts where cred is valid
}

type ValidationCheck struct {
	Valid    bool
	Error    string
	Latency  time.Duration
	Response string
}

// RunValidation validates all acquired credentials across multiple protocols
func RunValidation(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	
	if len(state.Creds) == 0 {
		fmt.Println(utils.WarningStyle.Render("[!] No credentials to validate"))
		result.Success = false
		return result
	}
	
	hosts := state.Hosts
	if len(hosts) == 0 {
		fmt.Println(utils.ErrorStyle.Render("[!] No hosts available for validation"))
		result.Success = false
		return result
	}
	
	// If target specified, validate against that host only
	if targetHost != "" {
		for _, h := range hosts {
			if h.IP == targetHost || h.Hostname == targetHost {
				hosts = []core.Host{h}
				break
			}
		}
	}
	
	fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("[*] Validating %d credentials against %d hosts...", len(state.Creds), len(hosts))))
	
	validatedCount := 0
	adminCount := 0
	
	for i, cred := range state.Creds {
		if cred.Validated {
			fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("[*] Skipping already validated: %s\\%s", cred.Domain, cred.Username)))
			continue
		}
		
		fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("\n[*] [%d/%d] Validating %s\\%s", i+1, len(state.Creds), cred.Domain, cred.Username)))
		
		valResult := validateCredential(cred, hosts)
		
		if valResult.SMB.Valid || valResult.LDAP.Valid || valResult.WinRM.Valid {
			validatedCount++
			cred.Validated = true
			
			// Update credential in state
			for j := range state.Creds {
				if state.Creds[j].Username == cred.Username && state.Creds[j].Domain == cred.Domain {
					state.Creds[j].Validated = true
					break
				}
			}
			
			// Create evidence
			protocols := []string{}
			if valResult.SMB.Valid {
				protocols = append(protocols, "SMB")
			}
			if valResult.LDAP.Valid {
				protocols = append(protocols, "LDAP")
			}
			if valResult.WinRM.Valid {
				protocols = append(protocols, "WinRM")
			}
			if valResult.RDP.Valid {
				protocols = append(protocols, "RDP")
			}
			
			adminStatus := ""
			if valResult.IsAdmin {
				adminCount++
				adminStatus = " [ADMIN]"
			}
			
			fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("  [+] Valid on: %s%s", strings.Join(protocols, ", "), adminStatus)))
			fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("  [+] Accessible hosts: %d", len(valResult.Hosts))))
			
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvCredValidated,
				Phase:      core.PhaseValidation,
				Source:     "multi_protocol",
				Key:        fmt.Sprintf("%s\\%s", cred.Domain, cred.Username),
				Value:      strings.Join(protocols, ","),
				Confidence: calculateConfidence(valResult),
				RawOutput:  formatValidationOutput(valResult),
				Timestamp:  time.Now(),
			})
		} else {
			fmt.Println(utils.ErrorStyle.Render("  [-] Invalid or inaccessible"))
			
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvCredValidated,
				Phase:      core.PhaseValidation,
				Source:     "multi_protocol",
				Key:        fmt.Sprintf("%s\\%s", cred.Domain, cred.Username),
				Value:      "invalid",
				Confidence: 0.0,
				Timestamp:  time.Now(),
			})
		}
	}
	
	fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("\n[+] Validation complete: %d/%d valid (%d admin)", validatedCount, len(state.Creds), adminCount)))
	
	result.Success = validatedCount > 0
	return result
}

// validateCredential tests a credential across multiple protocols and hosts
func validateCredential(cred core.Credential, hosts []core.Host) ValidationResult {
	valResult := ValidationResult{
		Credential: cred,
		Hosts:      []string{},
	}
	
	ctx := context.Background()
	
	// Test against each host
	for _, host := range hosts {
		target := tools.NetExecTarget{
			Host:     host.IP,
			Domain:   cred.Domain,
			Username: cred.Username,
			Password: cred.Secret,
			Hash:     cred.Hash,
		}
		
		// Test SMB
		if !valResult.SMB.Valid {
			target.Protocol = "smb"
			target.Port = 445
			start := time.Now()
			r, err := tools.NetExec.Run(ctx, target, "", nil)
			latency := time.Since(start)
			
			if err == nil && r.Success {
				valResult.SMB.Valid = true
				valResult.SMB.Latency = latency
				valResult.SMB.Response = r.Stdout
				valResult.Hosts = append(valResult.Hosts, host.IP)
				
				// Check for admin rights (Pwn3d! indicator)
				if strings.Contains(r.Stdout, "Pwn3d!") || strings.Contains(r.Stdout, "(Pwn3d!)") {
					valResult.IsAdmin = true
				}
			} else {
				if err != nil {
					valResult.SMB.Error = err.Error()
				} else {
					valResult.SMB.Error = r.Stderr
				}
			}
		}
		
		// Test LDAP
		if !valResult.LDAP.Valid {
			target.Protocol = "ldap"
			target.Port = 389
			start := time.Now()
			r, err := tools.NetExec.Run(ctx, target, "", nil)
			latency := time.Since(start)
			
			if err == nil && r.Success {
				valResult.LDAP.Valid = true
				valResult.LDAP.Latency = latency
				valResult.LDAP.Response = r.Stdout
				if !contains(valResult.Hosts, host.IP) {
					valResult.Hosts = append(valResult.Hosts, host.IP)
				}
			} else {
				if err != nil {
					valResult.LDAP.Error = err.Error()
				} else {
					valResult.LDAP.Error = r.Stderr
				}
			}
		}
		
		// Test WinRM (if SMB worked, likely WinRM will too)
		if valResult.SMB.Valid && !valResult.WinRM.Valid {
			target.Protocol = "winrm"
			target.Port = 5985
			start := time.Now()
			r, err := tools.NetExec.Run(ctx, target, "", nil)
			latency := time.Since(start)
			
			if err == nil && r.Success {
				valResult.WinRM.Valid = true
				valResult.WinRM.Latency = latency
				valResult.WinRM.Response = r.Stdout
				if !contains(valResult.Hosts, host.IP) {
					valResult.Hosts = append(valResult.Hosts, host.IP)
				}
				
				// WinRM access usually means admin
				if strings.Contains(r.Stdout, "Pwn3d!") {
					valResult.IsAdmin = true
				}
			} else {
				if err != nil {
					valResult.WinRM.Error = err.Error()
				} else {
					valResult.WinRM.Error = r.Stderr
				}
			}
		}
		
		// If we found valid creds on one host, continue testing other hosts for lateral movement
		if valResult.SMB.Valid || valResult.LDAP.Valid {
			continue
		}
	}
	
	return valResult
}

// calculateConfidence returns confidence score based on validation results
func calculateConfidence(vr ValidationResult) float64 {
	score := 0.0
	
	if vr.SMB.Valid {
		score += 0.4
	}
	if vr.LDAP.Valid {
		score += 0.3
	}
	if vr.WinRM.Valid {
		score += 0.2
	}
	if vr.RDP.Valid {
		score += 0.1
	}
	
	// Bonus for admin rights
	if vr.IsAdmin {
		score += 0.2
	}
	
	// Bonus for working on multiple hosts
	if len(vr.Hosts) > 1 {
		score += 0.1
	}
	
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// formatValidationOutput creates a summary string
func formatValidationOutput(vr ValidationResult) string {
	var lines []string
	
	if vr.SMB.Valid {
		lines = append(lines, fmt.Sprintf("SMB: Valid (%.2fs)", vr.SMB.Latency.Seconds()))
	}
	if vr.LDAP.Valid {
		lines = append(lines, fmt.Sprintf("LDAP: Valid (%.2fs)", vr.LDAP.Latency.Seconds()))
	}
	if vr.WinRM.Valid {
		lines = append(lines, fmt.Sprintf("WinRM: Valid (%.2fs)", vr.WinRM.Latency.Seconds()))
	}
	if vr.RDP.Valid {
		lines = append(lines, fmt.Sprintf("RDP: Valid (%.2fs)", vr.RDP.Latency.Seconds()))
	}
	
	if vr.IsAdmin {
		lines = append(lines, "Admin: YES")
	}
	
	lines = append(lines, fmt.Sprintf("Hosts: %s", strings.Join(vr.Hosts, ", ")))
	
	return strings.Join(lines, " | ")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
