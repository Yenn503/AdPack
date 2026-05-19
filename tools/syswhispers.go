package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type sysWhispersTool struct{}

var SysWhispers = sysWhispersTool{}

func (sysWhispersTool) Name() string { return "syswhispers" }

func (s sysWhispersTool) Available() bool { return s.pythonScript() != "" }

func (s sysWhispersTool) Validate() error {
	if !s.Available() {
		return &ToolError{Tool: "syswhispers", Op: "Validate", Err: fmt.Errorf("not available")}
	}
	return nil
}

func (sysWhispersTool) Capabilities() []Capability {
	return []Capability{CapSyscallGen}
}

func (s sysWhispersTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 1)
	go func() {
		defer close(ch)
		result, err := s.Run(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}

func (s sysWhispersTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	if len(req.Args) > 0 && req.Args[0] == "project" {
		sub := req
		sub.Args = req.Args[1:]
		return s.GenerateForProject(ctx, sub)
	}
	return s.GenerateStubs(ctx, req)
}

type SysWhispersConfig struct {
	OutputDir string
	Arch      string
	Functions []string
	Resolve   string
	Method    string
	Compiler  string
}

func DefaultSysWhispersConfig(outputDir string, functions []string) SysWhispersConfig {
	if outputDir == "" {
		outputDir = "syscalls"
	}
	if functions == nil {
		functions = []string{
			"NtOpenProcess", "NtOpenProcessToken", "NtDuplicateToken",
			"NtCreateProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory",
			"NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory",
			"NtResumeThread", "NtClose", "NtQuerySystemInformation",
			"NtQueryInformationProcess", "NtOpenFile", "NtCreateFile",
		}
	}
	return SysWhispersConfig{
		OutputDir: outputDir,
		Arch:      "x64",
		Resolve:   "recycled",
		Method:    "indirect",
		Compiler:  "mingw",
		Functions: functions,
	}
}

func (s sysWhispersTool) GenerateStubs(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	script := s.pythonScript()
	if script == "" {
		return nil, &ToolError{Tool: "syswhispers", Op: "GenerateStubs", Err: fmt.Errorf("script not found")}
	}
	cfg := DefaultSysWhispersConfig(req.WorkingDir, req.Args)
	if v, ok := req.Env["RESOLVE"]; ok {
		cfg.Resolve = v
	}
	fns := strings.Join(cfg.Functions, ",")
	args := []string{
		script,
		"--functions", fns,
		"--arch", cfg.Arch,
		"--resolver", cfg.Resolve,
		"--compiler", cfg.Compiler,
		"--out-dir", cfg.OutputDir,
	}
	cr := utils.RunCommandCtx(ctx, "python3", args)
	return cmdResultToExecResult(cr), nil
}

func (s sysWhispersTool) GenerateForProject(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	projectDir := req.WorkingDir
	if projectDir == "" {
		projectDir = "."
	}
	absDir, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, &ToolError{Tool: "syswhispers", Op: "GenerateForProject", Err: fmt.Errorf("resolving dir: %w", err)}
	}
	outDir := filepath.Join(absDir, "syscalls")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, &ToolError{Tool: "syswhispers", Op: "GenerateForProject", Err: fmt.Errorf("creating output dir: %w", err)}
	}
	req.WorkingDir = outDir
	r, err := s.GenerateStubs(ctx, req)
	if err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, &ToolError{Tool: "syswhispers", Op: "GenerateForProject", Err: fmt.Errorf("generation failed: %s", r.Stderr), ExitCode: r.ExitCode}
	}
	return r, nil
}

func (sysWhispersTool) pythonScript() string {
	candidates := []string{
		"/opt/syswhispers/syswhispers.py",
		filepath.Join(os.Getenv("HOME"), "tools", "syswhispers", "syswhispers.py"),
	}
	p, err := exec.LookPath("syswhispers")
	if err == nil {
		return p
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
