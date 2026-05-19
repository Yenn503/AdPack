package modules

import (
	"context"
	"adpack/core"
	"adpack/tools"
	"fmt"
	"strings"
	"time"
)

func RunSessionHarvest(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target available for session harvest. Run discovery first.")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No valid credentials found for session harvest. Run credential_acq first.")
		result.Success = false
		return result
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP, Port: 445,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Printf("[*] Harvesting sessions on %s...\n", host.IP)
	ctx := context.Background()
	r, err := tools.NetExec.Run(ctx, target, "--sessions", nil)
	if err == nil && r.Success {
		lines := strings.Split(r.Stdout, "\n")
		for _, line := range lines {
			if strings.Contains(line, "SESSION:") {
				parts := strings.Split(line, "SESSION:")
				if len(parts) > 1 {
					// Parse the session details
					sessionInfo := strings.TrimSpace(parts[1])
					// Assuming format: IP/Hostname User
					// Create a dummy session for now
					s := core.Session{
						HostID: host.ID,
						UserID: 0, // Should lookup the correct ID
						Source: "netexec_smb",
					}
					result.Sessions = append(result.Sessions, s)
					result.Evidence = append(result.Evidence, core.EvidenceEntry{
						Type: core.EvSessionFound, Phase: core.PhaseSessionHarvest,
						Source: "netexec_smb", Key: host.IP, Value: sessionInfo,
						Confidence: 1.0, Timestamp: time.Now(),
					})
				}
			}
		}
	} else {
		fmt.Printf("[!] Session harvest failed: %s\n", r.Stderr)
		result.Success = false
	}
	
	fmt.Printf("[+] Harvested %d sessions\n", len(result.Sessions))
	return result
}
