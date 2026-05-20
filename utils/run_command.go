package utils

import (
	"bytes"
	"context"
	"fmt"
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

func FindTool(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("tool %s not found in PATH", name)
	}
	return p, nil
}

func ToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
