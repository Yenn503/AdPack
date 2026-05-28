package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type miniPlasmaTool struct{}

var MiniPlasma = miniPlasmaTool{}

func (miniPlasmaTool) Name() string { return "MiniPlasma" }
func (miniPlasmaTool) Available() bool {
	return utils.ToolAvailable("MiniPlasma.exe") || utils.ToolAvailable("MiniPlasma")
}

type MiniPlasmaConfig struct {
	Binary string
	Stage  int
}

func DefaultMiniPlasmaConfig() MiniPlasmaConfig {
	return MiniPlasmaConfig{
		Binary: "MiniPlasma.exe",
	}
}

func (m miniPlasmaTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultMiniPlasmaConfig()
	if len(req.Args) > 0 {
		fmt.Sscanf(req.Args[0], "%d", &cfg.Stage)
	}
	args := []string{}
	if cfg.Stage > 0 {
		args = append(args, fmt.Sprintf("%d", cfg.Stage))
	}
	binary := cfg.Binary
	if resolved := utils.ResolveLocalPath(binary); resolved != "" {
		binary = resolved
	}
	r := utils.RunCommandCtx(ctx, binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "MiniPlasma", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}
