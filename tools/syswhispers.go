package tools

import (
	"adpack/utils"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type sysWhispersTool struct{}

var SysWhispers = sysWhispersTool{}

func (sysWhispersTool) Name() string {
	return "syswhispers"
}

func (s sysWhispersTool) Available() bool {
	return s.pythonScript() != ""
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

var resolveMethodMap = map[string]string{
	"hells_gate":    "hells",
	"halos_gate":    "halos",
	"tartarus_gate": "tartarus",
	"freshycalls":   "freshy",
	"recycledgate":  "recycled",
	"hw_breakpoint": "hwbp",
	"static":        "static",
}

func (s sysWhispersTool) GenerateStubs(cfg SysWhispersConfig) utils.CmdResult {
	script := s.pythonScript()
	fns := strings.Join(cfg.Functions, ",")
	args := []string{
		script,
		"--functions", fns,
		"--arch", cfg.Arch,
		"--resolver", cfg.Resolve,
		"--compiler", cfg.Compiler,
		"--out-dir", cfg.OutputDir,
	}
	return utils.RunCommandTimeout(30000000000, "python3", args)
}

func (s sysWhispersTool) GenerateForProject(projectDir string, functions []string, resolveMethod string) (string, error) {
	absDir, err := filepath.Abs(projectDir)
	if err != nil {
		return "", fmt.Errorf("syswhispers: resolving dir: %w", err)
	}
	outDir := filepath.Join(absDir, "syscalls")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("syswhispers: creating output dir: %w", err)
	}
	cfg := DefaultSysWhispersConfig(outDir, functions)
	if r, ok := resolveMethodMap[resolveMethod]; ok {
		cfg.Resolve = r
	} else if resolveMethod != "" {
		cfg.Resolve = resolveMethod
	}
	r := s.GenerateStubs(cfg)
	if !r.Success {
		return "", fmt.Errorf("syswhispers: generation failed: %s", r.Stderr)
	}
	return outDir, nil
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
