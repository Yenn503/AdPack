package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type roadreconTool struct{}

var Roadrecon = roadreconTool{}

func (roadreconTool) Name() string    { return "roadrecon" }
func (roadreconTool) Available() bool { return utils.ToolAvailable("roadrecon") }

func (roadreconTool) RunAuth(ctx context.Context, tenant, user, pass string) (*ExecutionResult, error) {
	return runTool(ctx, "roadrecon", []string{"auth", "-t", tenant, "-u", user, "-p", pass})
}

func (roadreconTool) RunDump(ctx context.Context) (*ExecutionResult, error) {
	return runTool(ctx, "roadrecon", []string{"dump"})
}

type azurehoundTool struct{}

var Azurehound = azurehoundTool{}

func (azurehoundTool) Name() string    { return "azurehound" }
func (azurehoundTool) Available() bool { return utils.ToolAvailable("azurehound") }

func (azurehoundTool) RunCollect(ctx context.Context, tenant, user, pass, outputFile string) (*ExecutionResult, error) {
	return runTool(ctx, "azurehound", []string{"-t", tenant, "-u", user, "-p", pass, "-o", outputFile})
}

type o365sprayTool struct{}

var O365spray = o365sprayTool{}

func (o365sprayTool) Name() string    { return "o365spray" }
func (o365sprayTool) Available() bool { return utils.ToolAvailable("o365spray") }

func (o365sprayTool) RunSpray(ctx context.Context, domain, userlist, password string) (*ExecutionResult, error) {
	return runTool(ctx, "o365spray", []string{"--spray", "-d", domain, "-U", userlist, "-p", password})
}

func runTool(ctx context.Context, name string, args []string) (*ExecutionResult, error) {
	cr := utils.RunCommandCtx(ctx, name, args)
	if !cr.Success {
		return cmdResultToExecResult(cr), fmt.Errorf("%s failed: %s", name, cr.Stderr)
	}
	return cmdResultToExecResult(cr), nil
}
