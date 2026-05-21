package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
)

type NetExecExecutor struct {
	target core.HostRef
	domain string
	user   string
	pass   string
	hash   string
}

func NewNetExecExecutor(target core.HostRef, domain, user, pass, hash string) core.Executor {
	return &NetExecExecutor{
		target: target,
		domain: domain,
		user:   user,
		pass:   pass,
		hash:   hash,
	}
}

func (e *NetExecExecutor) nxcTarget(protocol string) NetExecTarget {
	return NetExecTarget{
		Protocol: protocol,
		Host:     e.target.Name,
		Domain:   e.domain,
		Username: e.user,
		Password: e.pass,
		Hash:     e.hash,
	}
}

func (e *NetExecExecutor) Execute(ctx context.Context, action core.Action) core.ActionResult {
	t := e.nxcTarget("smb")
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}

	switch action.Method {
	case "command":
		r, err := NetExec.RunFailover(ctx, t, action.Artifact, timeout)
		if err != nil {
			return core.ActionResult{
				Success: false,
				Output:  r.Stdout,
				Stderr:  r.Stderr,
				Method:  r.Method,
				Error:   err.Error(),
			}
		}
		return core.ActionResult{
			Success:  r.Success,
			Output:   r.Stdout,
			Stderr:   r.Stderr,
			Method:   r.Method,
			ExitCode: r.ExitCode,
		}

	case "system_check":
		method, r, ok := NetExec.RunSystemCheck(ctx, t, timeout)
		if !ok {
			return core.ActionResult{
				Success: false,
				Output:  r.Stdout,
				Stderr:  r.Stderr,
				Method:  method,
			}
		}
		return core.ActionResult{
			Success: true,
			Output:  r.Stdout,
			Stderr:  r.Stderr,
			Method:  method,
		}

	case "put_file":
		if len(action.Arguments) == 0 {
			return core.ActionResult{Success: false, Error: "put_file: remote path required in action.Arguments[0]"}
		}
		r, err := NetExec.PutFile(ctx, t, action.Artifact, action.Arguments[0])
		if err != nil || !r.Success {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			return core.ActionResult{Success: false, Error: errStr, Output: r.Stdout, Stderr: r.Stderr}
		}
		return core.ActionResult{Success: true, Output: r.Stdout}

	case "run_binary":
		cmd := action.Artifact
		if len(action.Arguments) > 0 {
			cmd = action.Artifact + " " + strings.Join(action.Arguments, " ")
		}
		r, err := NetExec.RunFailover(ctx, t, cmd, timeout)
		if err != nil {
			return core.ActionResult{
				Success: false, Output: r.Stdout, Stderr: r.Stderr,
				Method: r.Method, Error: err.Error(),
			}
		}
		return core.ActionResult{
			Success: r.Success, Output: r.Stdout, Stderr: r.Stderr,
			Method: r.Method, ExitCode: r.ExitCode,
		}

	case "ldap_query":
		t = e.nxcTarget("ldap")
		args := action.Arguments
		if args == nil {
			args = []string{}
		}
		r, err := NetExec.Run(ctx, t, action.Artifact, args)
		if err != nil {
			return core.ActionResult{Success: false, Error: err.Error(), Stderr: r.Stderr, Output: r.Stdout}
		}
		return core.ActionResult{Success: r.Success, Output: r.Stdout, Stderr: r.Stderr}

	case "sc_create":
		svcName := ""
		if len(action.Arguments) > 0 {
			svcName = action.Arguments[0]
		}
		if svcName == "" {
			return core.ActionResult{Success: false, Error: "sc_create: service name required in action.Arguments[0]"}
		}
		cmd := fmt.Sprintf(`sc.exe create "%s" binPath="%s" type=kernel`,
			svcName, action.Artifact)
		r, err := NetExec.RunFailover(ctx, t, cmd, timeout)
		if err != nil {
			return core.ActionResult{Success: false, Error: err.Error()}
		}
		return core.ActionResult{Success: r.Success}

	case "sc_start":
		cmd := fmt.Sprintf(`sc.exe start %s`, action.Artifact)
		r, err := NetExec.RunFailover(ctx, t, cmd, timeout)
		if err != nil {
			return core.ActionResult{Success: false, Error: err.Error()}
		}
		return core.ActionResult{Success: r.Success}

	default:
		return core.ActionResult{Success: false, Error: fmt.Sprintf("unknown exec method: %s", action.Method)}
	}
}
