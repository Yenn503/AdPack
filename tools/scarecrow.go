package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type scareCrowTool struct{}

var ScareCrow = scareCrowTool{}

func (scareCrowTool) Name() string    { return "scarecrow" }
func (scareCrowTool) Available() bool { return utils.ToolAvailable("ScareCrow") || utils.ToolAvailable("ScareCrow.exe") }

func (scareCrowTool) Validate() error {
	if !ScareCrow.Available() {
		return &ToolError{Tool: "scarecrow", Op: "validate", Err: fmt.Errorf("ScareCrow not found")}
	}
	return nil
}

func (scareCrowTool) Capabilities() []Capability {
	return []Capability{CapShellcodeGen}
}

type ScareCrowConfig struct {
	Input       string
	Output      string
	LoaderType  string
	Domain      string
	Signed      bool
	Delay       int
	SandboxAmsi bool
	Obfuscation string
}

func DefaultScareCrowConfig(input, output string) ScareCrowConfig {
	return ScareCrowConfig{
		Input:       input,
		Output:      output,
		LoaderType:  "dll",
		Domain:      "windowsupdate.com",
		Signed:      true,
		Obfuscation: "aes",
		SandboxAmsi: true,
	}
}

func (s scareCrowTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultScareCrowConfig(req.Target, req.WorkingDir)
	if len(req.Args) > 0 {
		cfg.LoaderType = req.Args[0]
	}
	return s.GenerateLoader(ctx, cfg)
}

func (s scareCrowTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 1)
	go func() {
		defer close(ch)
		result, err := s.Run(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}

func (s scareCrowTool) GenerateLoader(ctx context.Context, cfg ScareCrowConfig) (*ExecutionResult, error) {
	args := []string{
		"-I", cfg.Input,
		"-O", cfg.Output,
		"-LoaderType", cfg.LoaderType,
		"-Domain", cfg.Domain,
	}
	if cfg.Signed {
		args = append(args, "-signed")
	}
	if cfg.Delay > 0 {
		args = append(args, "-delay", fmt.Sprintf("%d", cfg.Delay))
	}
	if cfg.SandboxAmsi {
		args = append(args, "-sandbox", "-amsi")
	}
	if cfg.Obfuscation != "" {
		args = append(args, "-obfu", cfg.Obfuscation)
	}
	cr := s.run(ctx, args...)
	if !cr.Success {
		return cmdResultToExecResult(cr), &ToolError{Tool: "scarecrow", Op: "generate", ExitCode: cr.ExitCode, Err: fmt.Errorf("%s", cr.Stderr)}
	}
	return cmdResultToExecResult(cr), nil
}

func (scareCrowTool) run(ctx context.Context, args ...string) utils.CmdResult {
	if utils.ToolAvailable("ScareCrow") {
		return utils.RunCommandCtx(ctx, "ScareCrow", args)
	} else if utils.ToolAvailable("ScareCrow.exe") {
		return utils.RunCommandCtx(ctx, "ScareCrow.exe", args)
	}
	return utils.CmdResult{Success: false, Stderr: "ScareCrow not found"}
}

func (s scareCrowTool) WrapShellcode(ctx context.Context, inputShellcode string) (*ExecutionResult, error) {
	absIn, err := filepath.Abs(inputShellcode)
	if err != nil {
		return nil, &ToolError{Tool: "scarecrow", Op: "wrap", Err: fmt.Errorf("resolving input: %w", err)}
	}
	if _, err := os.Stat(absIn); os.IsNotExist(err) {
		return nil, &ToolError{Tool: "scarecrow", Op: "wrap", Err: fmt.Errorf("input not found: %s", absIn)}
	}
	ext := filepath.Ext(absIn)
	base := strings.TrimSuffix(absIn, ext)
	outputName := filepath.Base(base + "_loader.dll")
	workDir := filepath.Dir(absIn)
	outputPath := filepath.Join(workDir, outputName)
	cfg := DefaultScareCrowConfig(absIn, outputPath)
	return s.GenerateLoader(ctx, cfg)
}
