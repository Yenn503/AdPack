package utils

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Success  bool
	Duration time.Duration
}

func RunCommand(name string, args ...string) CmdResult {
	return RunCommandTimeout(120*time.Second, name, args)
}

func RunCommandTimeout(d time.Duration, name string, args []string) CmdResult {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return RunCommandCtx(ctx, name, args)
}

func RunCommandCtx(ctx context.Context, name string, args []string) CmdResult {
	cmd := exec.CommandContext(ctx, name, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	start := time.Now()
	err := cmd.Run()
	r := CmdResult{
		Stdout: strings.TrimSpace(so.String()), Stderr: strings.TrimSpace(se.String()),
		Duration: time.Since(start),
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			r.Stderr = "Command timed out: " + r.Stderr
		}
		if ee, ok := err.(*exec.ExitError); ok {
			r.ExitCode = ee.ExitCode()
		} else {
			r.ExitCode = -1
		}
		r.Success = false
	} else {
		r.ExitCode = 0
		r.Success = true
	}
	return r
}

// RunCommandRetry runs a command with exponential backoff + jitter.
// Returns the first successful result. maxRetries=3, base=1s, max=30s.
func RunCommandRetry(name string, args []string, maxRetries int) CmdResult {
	if maxRetries < 1 {
		maxRetries = 3
	}
	baseSleep := time.Second
	maxSleep := 30 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		slog.Debug("run command", "tool", name, "attempt", attempt+1, "max", maxRetries+1)
		r := RunCommand(name, args...)
		if r.Success {
			return r
		}
		if attempt == maxRetries {
			slog.Warn("command failed after retries", "tool", name, "attempts", attempt+1, "error", r.Stderr)
			return r
		}
		// Exponential backoff + jitter: sleep = min(base * 2^attempt + rand(0,base), max)
		sleep := baseSleep * time.Duration(math.Pow(2, float64(attempt)))
		jitter := time.Duration(rand.Int63n(int64(baseSleep)))
		sleep += jitter
		if sleep > maxSleep {
			sleep = maxSleep
		}
		slog.Debug("retrying after backoff", "tool", name, "sleep", sleep, "attempt", attempt+1)
		time.Sleep(sleep)
	}
	return CmdResult{Success: false}
}

// ResolveLocalPath finds a local artifact file by checking:
//  1. CWD directly (name as-is)
//  2. exe/ subdirectory of CWD
//  3. exe/ subdirectory of the running adpack binary's location
//  4. exe/ subdirectory of the project root (found by walking up from CWD looking for go.mod)
//
// Returns the resolved path or empty string if not found anywhere.
// Unlike FindTool/ToolAvailable this does NOT require the executable bit —
// it works for DLLs and other non-executable payloads too.
func ResolveLocalPath(name string) string {
	if fi, err := os.Stat(name); err == nil && !fi.IsDir() {
		return name
	}
	exePath := filepath.Join("exe", name)
	if fi, err := os.Stat(exePath); err == nil && !fi.IsDir() {
		return exePath
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		exePath2 := filepath.Join(exeDir, "exe", name)
		if fi, err := os.Stat(exePath2); err == nil && !fi.IsDir() {
			return exePath2
		}
		exePath3 := filepath.Join(exeDir, "..", "exe", name)
		if fi, err := os.Stat(exePath3); err == nil && !fi.IsDir() {
			return exePath3
		}
	}
	// Walk up from CWD looking for go.mod -> project root -> exe/name
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for {
			if fi, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !fi.IsDir() {
				if fi, err := os.Stat(filepath.Join(dir, "exe", name)); err == nil && !fi.IsDir() {
					return filepath.Join(dir, "exe", name)
				}
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	// Fallback: check PATH via exec.LookPath (covers /usr/local/bin, etc.)
	// This is the same resolution as FindTool/ToolAvailable — it's a bug if
	// Deploy can't find a binary that ToolAvailable reports as present.
	if p, err := exec.LookPath(name); err == nil {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// FindTool returns the resolved path to `name` if it is executable, checking
// PATH first and then ResolveLocalPath. A file that exists but has no execute
// bit set (Unix) is treated as "not found" because invoking it would yield a
// "permission denied" error at exec time, which is harder to debug than a
// clean "not found" up front.
func FindTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	// Fallback: ResolveLocalPath which checks CWD, exe/CWD, and exe/bindir.
	// We require the executable bit so e.g. a stray data file with the same
	// basename as the tool isn't reported as "available".
	p := ResolveLocalPath(name)
	if p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("tool %s not found in PATH, CWD, or exe/", name)
}

// ToolAvailable mirrors FindTool but returns only a bool. Same executability
// requirement as FindTool — a non-executable file with the same name as a tool
// is not "available".
func ToolAvailable(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	p := ResolveLocalPath(name)
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode()&0o111 != 0
}
