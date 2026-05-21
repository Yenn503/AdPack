package core

import (
	"context"
	"time"
)

type Action struct {
	Target    HostRef
	Method    string // smb, winrm, local, task
	Artifact  string // binary path, script, or command string
	Arguments []string
	Timeout   time.Duration
}

type ActionResult struct {
	Success  bool
	Output   string
	Stderr   string
	Method   string
	ExitCode int
	Error    string
	Evidence *ExecutionEvidence
}

type Executor interface {
	Execute(ctx context.Context, action Action) ActionResult
}

type ExecutorFactory func(target HostRef, domain, user, pass, hash string) Executor

type ExecutorFunc func(ctx context.Context, action Action) ActionResult

func (f ExecutorFunc) Execute(ctx context.Context, action Action) ActionResult {
	return f(ctx, action)
}
