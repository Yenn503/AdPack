package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type donutTool struct{}

var Donut = donutTool{}

func (donutTool) Name() string    { return "donut" }
func (donutTool) Available() bool { return utils.ToolAvailable("donut") }

type DonutConfig struct {
	Input       string
	Output      string
	Arch        string
	Entropy     string
	Compression int
	Bypass      string
	Class       string
	Method      string
	Params      string
	UnicodeArg  bool
}

func DefaultDonutConfig(input string) DonutConfig {
	return DonutConfig{
		Input:       input,
		Output:      input + ".bin",
		Arch:        "x64",
		Entropy:     "random",
		Compression: 3,
	}
}

func (d donutTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	return d.GenerateShellcode(ctx, req)
}

func (d donutTool) GenerateShellcode(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	args := make([]string, len(req.Args))
	copy(args, req.Args)
	cr := utils.RunCommandCtx(ctx, "donut", args)
	if !cr.Success {
		return cmdResultToExecResult(cr), &ToolError{
			Tool: "donut", Op: "GenerateShellcode",
			Err:      fmt.Errorf("exit code %d: %s", cr.ExitCode, cr.Stderr),
			ExitCode: cr.ExitCode,
		}
	}
	return cmdResultToExecResult(cr), nil
}

func (d donutTool) WrapPE(ctx context.Context, pePath string, params string) (*ExecutionResult, error) {
	absIn, err := filepath.Abs(pePath)
	if err != nil {
		return nil, &ToolError{
			Tool: "donut", Op: "WrapPE",
			Err: fmt.Errorf("resolving input path: %w", err),
		}
	}
	if _, err := os.Stat(absIn); os.IsNotExist(err) {
		return nil, &ToolError{
			Tool: "donut", Op: "WrapPE",
			Err: fmt.Errorf("input not found: %s", absIn),
		}
	}
	outPath := absIn + ".bin"
	cfg := DefaultDonutConfig(absIn)
	cfg.Params = params
	cfg.Output = outPath
	r := utils.RunCommandCtx(ctx, "donut", buildDonutArgs(cfg))
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{
			Tool: "donut", Op: "WrapPE",
			Err:      fmt.Errorf("generation failed: %s", r.Stderr),
			ExitCode: r.ExitCode,
		}
	}
	result := cmdResultToExecResult(r)
	result.Artifacts = append(result.Artifacts, Artifact{
		Path:     outPath,
		MIMEType: "application/octet-stream",
	})
	return result, nil
}

func buildDonutArgs(cfg DonutConfig) []string {
	args := []string{
		"-f", cfg.Input,
		"-o", cfg.Output,
		"-a", cfg.Arch,
		"-e", cfg.Entropy,
	}
	if cfg.Compression > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", cfg.Compression))
	}
	if cfg.Bypass != "" {
		args = append(args, "-b", cfg.Bypass)
	}
	if cfg.Class != "" {
		args = append(args, "--class", cfg.Class)
	}
	if cfg.Method != "" {
		args = append(args, "--method", cfg.Method)
	}
	if cfg.Params != "" {
		args = append(args, "-p", cfg.Params)
	}
	if cfg.UnicodeArg {
		args = append(args, "-u")
	}
	return args
}

func (d donutTool) Validate() error {
	if !d.Available() {
		return &ToolError{
			Tool: "donut", Op: "Validate",
			Err: fmt.Errorf("donut not found in PATH"),
		}
	}
	return nil
}

func (d donutTool) Capabilities() []Capability {
	return []Capability{CapDonut, CapShellcodeGen}
}

func (d donutTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 1)
	go func() {
		defer close(ch)
		result, err := d.Run(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}
