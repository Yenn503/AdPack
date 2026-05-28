package core

import (
	"context"
	"time"
)

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Error    string
}

type Transport interface {
	Exec(ctx context.Context, target HostRef, command string, timeout time.Duration) ExecResult
	Upload(ctx context.Context, target HostRef, data []byte, remoteDir string, remoteName string) (remotePath string, err error)
	Download(ctx context.Context, target HostRef, remotePath string) (data []byte, err error)
	Type() string
}
