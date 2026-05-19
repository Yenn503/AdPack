package tools

import (
	"context"
	"adpack/utils"
	"fmt"
)

type miniPlasmaTool struct{}

var MiniPlasma = miniPlasmaTool{}

func (miniPlasmaTool) Name() string    { return "MiniPlasma" }
func (miniPlasmaTool) Available() bool {
	return utils.ToolAvailable("MiniPlasma.exe") || utils.ToolAvailable("MiniPlasma")
}

func (miniPlasmaTool) Validate() error {
	if !MiniPlasma.Available() {
		return &ToolError{Tool: "MiniPlasma", Op: "validate", Err: fmt.Errorf("MiniPlasma.exe not found")}
	}
	return nil
}

func (miniPlasmaTool) Capabilities() []Capability {
	return []Capability{CapPrivEsc}
}

func (m miniPlasmaTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 1)
	go func() {
		defer close(ch)
		result, err := m.Run(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
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
	r := utils.RunCommandCtx(ctx, cfg.Binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "MiniPlasma", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}
