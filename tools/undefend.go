package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type unDefendTool struct{}

var UnDefend = unDefendTool{}

func (unDefendTool) Name() string { return "UnDefend" }
func (unDefendTool) Available() bool {
	return utils.ToolAvailable("UnDefend.exe") || utils.ToolAvailable("UnDefend") || utils.ToolAvailable("undefend")
}

type UnDefendConfig struct {
	Binary string
	Kill   bool
}

func DefaultUnDefendConfig() UnDefendConfig {
	return UnDefendConfig{
		Binary: "UnDefend.exe",
	}
}

func (u unDefendTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultUnDefendConfig()
	if len(req.Args) > 0 {
		cfg.Kill = req.Args[0] == "--kill"
	}
	var args []string
	if cfg.Kill {
		args = []string{"--kill"}
	}
	r := utils.RunCommandCtx(ctx, cfg.Binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "UnDefend", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}

func (u unDefendTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string, kill bool) (*ExecutionResult, error) {
	cmd := remotePath
	if kill {
		cmd += " --kill"
	}
	cr, err := NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, cmd)})
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "UnDefend", Op: "exec_remote", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}
