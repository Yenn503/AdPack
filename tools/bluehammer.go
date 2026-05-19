package tools

import (
	"context"
	"adpack/utils"
	"fmt"
)

type blueHammerTool struct{}

var BlueHammer = blueHammerTool{}

func (blueHammerTool) Name() string    { return "BlueHammer" }
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

func (b blueHammerTool) Run(cfg BlueHammerConfig) utils.CmdResult {
	args := []string{}
	if cfg.SessionID > 0 {
		args = append(args, fmt.Sprintf("%d", cfg.SessionID))
	}
	return utils.RunCommand(cfg.Binary, args...)
}

func (b blueHammerTool) DeployViaSMB(ctx context.Context, target NetExecTarget, localPath, remoteDir string) (utils.CmdResult, error) {
	if !b.Available() {
		return utils.CmdResult{Success: false, Stderr: "FunnyApp.exe not found locally"}, fmt.Errorf("FunnyApp.exe not found locally")
	}
	return NetExec.PutFile(ctx, target, localPath, remoteDir)
}

func (b blueHammerTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string) (utils.CmdResult, error) {
	return NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, remotePath)})
}
