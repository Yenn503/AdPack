package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type blueHammerTool struct{}

var BlueHammer = blueHammerTool{}

func (blueHammerTool) Name() string { return "BlueHammer" }
func (blueHammerTool) Available() bool {
	return utils.ToolAvailable("FunnyApp.exe") || utils.ToolAvailable("BlueHammer.exe") || utils.ToolAvailable("bluehammer")
}

type BlueHammerConfig struct {
	Binary    string
	SessionID int
}

func DefaultBlueHammerConfig() BlueHammerConfig {
	return BlueHammerConfig{
		Binary: "FunnyApp.exe",
	}
}

func (b blueHammerTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultBlueHammerConfig()
	if len(req.Args) > 0 {
		fmt.Sscanf(req.Args[0], "%d", &cfg.SessionID)
	}
	args := []string{}
	if cfg.SessionID > 0 {
		args = append(args, fmt.Sprintf("%d", cfg.SessionID))
	}
	r := utils.RunCommandCtx(ctx, cfg.Binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "BlueHammer", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}

func (b blueHammerTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string) (*ExecutionResult, error) {
	cr, err := NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, remotePath)})
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "BlueHammer", Op: "exec_remote", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}
