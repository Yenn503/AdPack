package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type teamsPhisherTool struct{}

var TeamsPhisher = teamsPhisherTool{}

type TeamsPhishConfig struct {
	AttackerDomain string
	TargetsFile    string
	Message        string
	AttachmentPath string
	OPSECDelay     int
	PreviewMode    bool
}

func (teamsPhisherTool) Name() string { return "TeamsPhisher" }

func (teamsPhisherTool) Available() bool {
	return utils.ToolAvailable("python3") && utils.ResolveLocalPath("TeamsPhisher.py") != ""
}

func (teamsPhisherTool) RunPhish(ctx context.Context, config TeamsPhishConfig) (utils.CmdResult, error) {
	scriptPath := utils.ResolveLocalPath("TeamsPhisher.py")
	if scriptPath == "" {
		return utils.CmdResult{}, fmt.Errorf("TeamsPhisher.py not found")
	}

	args := []string{
		scriptPath,
		"--attacker-domain", config.AttackerDomain,
		"--targets", config.TargetsFile,
		"--message", config.Message,
		"--attachment", config.AttachmentPath,
	}
	if config.OPSECDelay > 0 {
		args = append(args, "--opsec-delay", fmt.Sprintf("%d", config.OPSECDelay))
	}
	if config.PreviewMode {
		args = append(args, "--preview-mode")
	}

	cr := utils.RunCommandCtx(ctx, "python3", args)
	if !cr.Success {
		return cr, fmt.Errorf("teamsphisher failed: %s", cr.Stderr)
	}
	return cr, nil
}
