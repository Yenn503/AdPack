package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type phantomKillerTool struct{}

var PhantomKiller = phantomKillerTool{}

func (phantomKillerTool) Name() string { return "PhantomKiller" }
func (phantomKillerTool) Available() bool {
	return utils.ToolAvailable("PhantomKiller.exe") || utils.ToolAvailable("PhantomKiller")
}

type PhantomKillerMode string

const (
	PhantomKillerModeLoad PhantomKillerMode = "load"
	PhantomKillerModeKill PhantomKillerMode = "kill"
)

type PhantomKillerConfig struct {
	Binary string
	Driver string
	PID    int
	Mode   PhantomKillerMode
}

func DefaultPhantomKillerConfig() PhantomKillerConfig {
	return PhantomKillerConfig{
		Binary: "PhantomKiller.exe",
		Driver: "PhantomKiller.sys",
	}
}

func (p phantomKillerTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultPhantomKillerConfig()
	if len(req.Args) > 0 {
		cfg.Mode = PhantomKillerMode(req.Args[0])
	}
	if len(req.Args) > 1 {
		fmt.Sscanf(req.Args[1], "%d", &cfg.PID)
	}
	args := []string{}
	if cfg.Mode == PhantomKillerModeKill && cfg.PID > 0 {
		args = append(args, fmt.Sprintf("%d", cfg.PID))
	}
	r := utils.RunCommandCtx(ctx, cfg.Binary, args)
	if !r.Success {
		return cmdResultToExecResult(r), &ToolError{Tool: "PhantomKiller", Op: "run", ExitCode: r.ExitCode, Err: fmt.Errorf("%s", r.Stderr)}
	}
	return cmdResultToExecResult(r), nil
}

func (p phantomKillerTool) ExecRemote(ctx context.Context, target NetExecTarget, remotePath string, mode PhantomKillerMode, pid int) (*ExecutionResult, error) {
	cmd := remotePath
	if mode == PhantomKillerModeKill && pid > 0 {
		cmd += fmt.Sprintf(" %d", pid)
	}
	cr, err := NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf(`start /B %s`, cmd)})
	if err != nil {
		return cmdResultToExecResult(cr), &ToolError{Tool: "PhantomKiller", Op: "exec_remote", Err: err, ExitCode: cr.ExitCode}
	}
	return cmdResultToExecResult(cr), nil
}
