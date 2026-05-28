package tools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"adpack/utils"
)

type nxcTool struct{}

var NetExec = nxcTool{}

func (nxcTool) Name() string { return "netexec" }
func (nxcTool) Available() bool {
	_, err := utils.FindTool("netexec")
	return err == nil
}

type NetExecTarget struct {
	Protocol string // smb, ldap, winrm, mssql
	Host     string
	Port     int
	Domain   string
	Username string
	Password string
	Hash     string
}

// NxcAuthSucceeded inspects nxc stdout/stderr to determine whether the
// authentication step itself worked. nxc exits with code 0 even when auth
// fails (it just prints `[-] domain\user:pass` and moves on), so a naive
// `r.Success` check yields false positives for every command that depends on
// a working session.
//
// Returns true only if a positive auth line is present AND no negative auth
// line is present for the same principal. The caller passes the actual
// username it sent so we don't get fooled by null-session probes that nxc
// adds at startup.
func NxcAuthSucceeded(out, username string) bool {
	if out == "" {
		return false
	}
	pos := false
	for _, line := range strings.Split(out, "\n") {
		// Per-principal positive marker, e.g.
		//   SMB ... [+] dom\user:pass
		// We do not need to match the whole user — nxc may print just `\:`
		// for null auth; restrict to lines that mention the username we sent.
		if strings.Contains(line, "[+]") && strings.Contains(line, username) {
			pos = true
		}
		// Hard auth failure markers.
		if strings.Contains(line, "[-]") && strings.Contains(line, username) {
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
					return false
				}
			}
		}
	}
	return pos
}

// NxcCommandSucceeded checks whether nxc actually executed an `-x <cmd>`
// shell command on the remote host. nxc on a non-admin auth simply skips
// the exec phase silently and exits 0; we need stronger evidence than the
// process exit code.
//
// Strong evidence: nxc prints `Executed command via <METHOD>` *or* the
// stdout contains a typical Windows identity tag like `nt authority\` /
// a `domain\user` style line that only appears in real command output.
func NxcCommandSucceeded(out string) bool {
	if out == "" {
		return false
	}
	lo := strings.ToLower(out)
	if strings.Contains(lo, "executed command via") ||
		strings.Contains(lo, "command executed with no output") {
		return true
	}
	// Fallback: real `whoami`-style output contains a domain\user token on
	// its own line (the leading `[*]` from the protocol summary doesn't).
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		// Skip nxc framing.
		if t == "" || strings.HasPrefix(t, "[") {
			continue
		}
		// Anything that looks like `domain\username` *not* followed by `:`
		// (which would be the auth banner) is real command output.
		if i := strings.IndexByte(t, '\\'); i > 0 && i < len(t)-1 {
			if !strings.Contains(t[i:], ":") {
				return true
			}
		}
	}
	return false
}

func (n nxcTool) Run(ctx context.Context, target NetExecTarget, subcmd string, extraArgs []string) (utils.CmdResult, error) {
	args := []string{target.Protocol, target.Host}
	if target.Port > 0 {
		args = append(args, fmt.Sprintf("--port=%d", target.Port))
	}
	if target.Domain != "" {
		args = append(args, "-d", target.Domain)
	}
	if target.Username != "" {
		args = append(args, "-u", target.Username)
	}
	if target.Password != "" {
		args = append(args, "-p", target.Password)
	}
	if target.Hash != "" {
		args = append(args, "-H", target.Hash)
	}
	if subcmd != "" {
		args = append(args, subcmd)
	}
	args = append(args, extraArgs...)
	r := utils.RunCommandCtx(ctx, "netexec", args)
	if !r.Success {
		return r, fmt.Errorf("netexec failed: %s", r.Stderr)
	}

	combined := r.Stdout + "\n" + r.Stderr

	// Validate auth evidence when credentials are provided. nxc exits 0 even
	// on auth failure (it prints a [-] line and moves on), so exit code alone
	// is insufficient. This check catches false-positive auth probes that
	// would otherwise poison planner state and confidence scoring.
	if target.Username != "" && !NxcAuthSucceeded(combined, target.Username) {
		r.Success = false
		return r, fmt.Errorf("auth failed for %s\\%s on %s",
			target.Domain, target.Username, target.Host)
	}

	// Validate execution evidence for remote command execution (-x/-X).
	// nxc exits 0 even when the user lacks admin rights and the command
	// silently no-ops. This catches false-positive exec results that
	// would make deploy/lateral/persistence look successful when they
	// did nothing.
	// Check both subcmd (direct -x/-X) and extraArgs (used by --exec-method).
	if subcmd == "-x" || subcmd == "-X" {
		if !NxcCommandSucceeded(combined) {
			r.Success = false
			return r, fmt.Errorf("command execution failed on %s (not admin?)", target.Host)
		}
	}
	for _, a := range extraArgs {
		if a == "-x" || a == "-X" {
			if !NxcCommandSucceeded(combined) {
				r.Success = false
				return r, fmt.Errorf("command execution failed on %s (not admin?)", target.Host)
			}
			break
		}
	}

	return r, nil
}

func (n nxcTool) PutFile(ctx context.Context, target NetExecTarget, localPath, remoteDir string) (utils.CmdResult, error) {
	// filepath.Base is OS-aware (handles both / and \ on Windows operator boxes).
	base := filepath.Base(localPath)
	if base == "." || base == "/" || base == `\` {
		base = "payload.bin"
	}

	remotePath := strings.TrimPrefix(remoteDir, `C:\`)
	remotePath = strings.TrimPrefix(remotePath, `c:\`)
	remotePath = strings.TrimPrefix(remotePath, `C$\`)
	remotePath = strings.TrimLeft(remotePath, `/\`)

	// Only treat remoteDir as a directory when it has an explicit trailing
	// separator (\ or /). This check uses strings.HasSuffix to detect the
	// trailing separator, avoiding misclassification of extensionless executables.
	if strings.HasSuffix(remoteDir, `\`) || strings.HasSuffix(remoteDir, `/`) {
		if remotePath != "" {
			remotePath = strings.TrimRight(remotePath, `/\`) + `\` + base
		} else {
			remotePath = base
		}
	}

	fmt.Printf("[*] PutFile: %s → %s\n", localPath, remotePath)
	return n.Run(ctx, target, "--put-file", []string{localPath, remotePath})
}

func (n nxcTool) GetFile(ctx context.Context, target NetExecTarget, remotePath, localDir string) (utils.CmdResult, error) {
	return n.Run(ctx, target, "--get-file", []string{remotePath, localDir})
}

// ExecMethodOrder is the canonical failover sequence for remote command execution.
// wmiexec runs as the authenticated user; smbexec/atexec run as SYSTEM (service
// or task scheduler). Order chosen for stealth → reliability tradeoff.
var ExecMethodOrder = []string{"wmiexec", "smbexec", "atexec"}

// FailoverResult captures which exec-method actually returned output, useful for
// downstream parsing (e.g. SYSTEM-context detection) and evidence logging.
type FailoverResult struct {
	utils.CmdResult
	Method string
}

// RunFailover executes a shell command on the target trying each exec-method
// in order until one succeeds within the per-attempt timeout. Returns the first
// successful result, or the last attempted result if all failed.
//
// Use this for any remote command where the *output* matters. For fire-and-forget
// payloads, prefer Run with `start /B` directly so you don't pay the failover cost.
func (n nxcTool) RunFailover(ctx context.Context, target NetExecTarget, command string, perAttempt time.Duration) (FailoverResult, error) {
	if perAttempt <= 0 {
		perAttempt = 45 * time.Second
	}
	var last FailoverResult
	var lastErr error
	for _, method := range ExecMethodOrder {
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		r, err := n.Run(attemptCtx, target, "--exec-method", []string{method, "-x", command})
		cancel()
		last = FailoverResult{CmdResult: r, Method: method}
		lastErr = err
		if err == nil && r.Success {
			return last, nil
		}
		// Don't keep retrying if the parent context was cancelled
		if ctx.Err() != nil {
			return last, ctx.Err()
		}
	}
	return last, lastErr
}
