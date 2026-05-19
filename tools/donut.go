package tools

import (
	"adpack/utils"
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
	Arch        string // x86, x64, x86+64
	Entropy     string // default, random
	Compression int    // 1-3
	Bypass      string // 1,2,3 (AMSIIndex)
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

func (d donutTool) GenerateShellcode(cfg DonutConfig) utils.CmdResult {
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
	return utils.RunCommand("donut", args...)
}

func (d donutTool) WrapPE(pePath string, params string) (string, error) {
	absIn, err := filepath.Abs(pePath)
	if err != nil {
		return "", fmt.Errorf("donut: resolving input path: %w", err)
	}
	if _, err := os.Stat(absIn); os.IsNotExist(err) {
		return "", fmt.Errorf("donut: input not found: %s", absIn)
	}
	outPath := absIn + ".bin"
	cfg := DefaultDonutConfig(absIn)
	cfg.Params = params
	cfg.Output = outPath
	r := d.GenerateShellcode(cfg)
	if !r.Success {
		return "", fmt.Errorf("donut: generation failed: %s", r.Stderr)
	}
	return outPath, nil
}
