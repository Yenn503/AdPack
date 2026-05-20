package tools

import (
	"adpack/utils"
	"time"
)

// ExecutionRequest carries inputs to a tool's Run method. Only the fields used
// by current callers are kept here — earlier iterations included campaign IDs,
// telemetry hooks and a tool registry that were never consumed.
type ExecutionRequest struct {
	Timeout time.Duration
	Evasion string
	Env     map[string]string
	Args    []string
}

// ExecutionResult is the canonical return shape for every Run-style tool method.
type ExecutionResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Success   bool
	Duration  time.Duration
	Artifacts []Artifact
}

// Artifact records a file produced by a tool (e.g. a Donut shellcode blob).
type Artifact struct {
	Path     string
	MIMEType string
	Size     int64
	Hash     string
}

// cmdResultToExecResult is the universal adapter from utils.CmdResult to
// ExecutionResult. Lives here (not per-tool) so every tool file uses the same one.
func cmdResultToExecResult(cr utils.CmdResult) *ExecutionResult {
	return &ExecutionResult{
		Stdout:   cr.Stdout,
		Stderr:   cr.Stderr,
		ExitCode: cr.ExitCode,
		Success:  cr.Success,
		Duration: cr.Duration,
	}
}
