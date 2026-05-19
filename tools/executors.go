package tools

import (
	"context"
	"fmt"

	"adpack/utils"
)

type LocalExecutor struct {
	Registry *Registry
}

func NewLocalExecutor(reg *Registry) *LocalExecutor {
	return &LocalExecutor{Registry: reg}
}

func (e *LocalExecutor) Protocol() string { return "local" }

func (e *LocalExecutor) Execute(ctx context.Context, req ExecCommandRequest) (*ExecutionResult, error) {
	cr := utils.RunCommandCtx(ctx, req.Command, req.Args)
	if !cr.Success {
		return cmdResultToExecResult(cr), fmt.Errorf("%s failed: %s", req.Command, cr.Stderr)
	}
	return cmdResultToExecResult(cr), nil
}

func (e *LocalExecutor) ExecuteStream(ctx context.Context, req ExecCommandRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 16)
	go func() {
		defer close(ch)
		result, err := e.Execute(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}

type SMBExecutor struct {
	Registry *Registry
	Target   NetExecTarget
}

func NewSMBExecutor(reg *Registry, target NetExecTarget) *SMBExecutor {
	t := target
	if t.Protocol == "" {
		t.Protocol = "smb"
	}
	return &SMBExecutor{Registry: reg, Target: t}
}

func (e *SMBExecutor) Protocol() string { return "smb" }

func (e *SMBExecutor) Execute(ctx context.Context, req ExecCommandRequest) (*ExecutionResult, error) {
	cr, err := NetExec.Run(ctx, e.Target, "-x", append([]string{req.Command}, req.Args...))
	if err != nil {
		return cmdResultToExecResult(cr), err
	}
	return cmdResultToExecResult(cr), nil
}

func (e *SMBExecutor) ExecuteStream(ctx context.Context, req ExecCommandRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 16)
	go func() {
		defer close(ch)
		result, err := e.Execute(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}

func (e *SMBExecutor) PutFile(ctx context.Context, localPath, remoteDir string) (*ExecutionResult, error) {
	cr, err := NetExec.PutFile(ctx, e.Target, localPath, remoteDir)
	if err != nil {
		return cmdResultToExecResult(cr), err
	}
	return cmdResultToExecResult(cr), nil
}

func (e *SMBExecutor) GetFile(ctx context.Context, remotePath, localDir string) (*ExecutionResult, error) {
	cr, err := NetExec.GetFile(ctx, e.Target, remotePath, localDir)
	if err != nil {
		return cmdResultToExecResult(cr), err
	}
	return cmdResultToExecResult(cr), nil
}

type WinRMExecutor struct {
	Registry *Registry
	Target   NetExecTarget
}

func NewWinRMExecutor(reg *Registry, target NetExecTarget) *WinRMExecutor {
	t := target
	if t.Protocol == "" {
		t.Protocol = "winrm"
	}
	return &WinRMExecutor{Registry: reg, Target: t}
}

func (e *WinRMExecutor) Protocol() string { return "winrm" }

func (e *WinRMExecutor) Execute(ctx context.Context, req ExecCommandRequest) (*ExecutionResult, error) {
	cr, err := NetExec.Run(ctx, e.Target, "-x", append([]string{req.Command}, req.Args...))
	if err != nil {
		return cmdResultToExecResult(cr), err
	}
	return cmdResultToExecResult(cr), nil
}

func (e *WinRMExecutor) ExecuteStream(ctx context.Context, req ExecCommandRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 16)
	go func() {
		defer close(ch)
		result, err := e.Execute(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}

type ExecutorFactory struct {
	Registry *Registry
}

func NewExecutorFactory(reg *Registry) *ExecutorFactory {
	return &ExecutorFactory{Registry: reg}
}

func (f *ExecutorFactory) Local() *LocalExecutor {
	return NewLocalExecutor(f.Registry)
}

func (f *ExecutorFactory) SMB(target NetExecTarget) *SMBExecutor {
	return NewSMBExecutor(f.Registry, target)
}

func (f *ExecutorFactory) WinRM(target NetExecTarget) *WinRMExecutor {
	return NewWinRMExecutor(f.Registry, target)
}

func (f *ExecutorFactory) ForTarget(target NetExecTarget, preferredProtocol string) Executor {
	switch preferredProtocol {
	case "smb":
		return f.SMB(target)
	case "winrm":
		return f.WinRM(target)
	default:
		return f.Local()
	}
}
