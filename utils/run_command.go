package utils

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
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

// FindTool returns the resolved path to `name` if it is executable, checking
// PATH first and then the current working directory. A file that exists but
// has no execute bit set (Unix) is treated as "not found" because invoking it
// would yield a "permission denied" error at exec time, which is harder to
// debug than a clean "not found" up front.
func FindTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	// Fallback: a relative or absolute path that exists in CWD. We require the
	// executable bit (mode & 0111) so e.g. a stray data file with the same
	// basename as the tool isn't reported as "available".
	if fi, err := os.Stat(name); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
		return name, nil
	}
	return "", fmt.Errorf("tool %s not found in PATH or not executable in CWD", name)
}

// ToolAvailable mirrors FindTool but returns only a bool. Same executability
// requirement as FindTool — a non-executable file with the same name as a tool
// is not "available".
func ToolAvailable(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	fi, err := os.Stat(name)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode()&0o111 != 0
}
