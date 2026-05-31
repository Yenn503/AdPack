package local

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
)

type Option func(*LocalTransport)

func WithTiming(t core.TimingConfig) Option {
	return func(lt *LocalTransport) {
		lt.timing = t
	}
}

type LocalTransport struct {
	domain string
	user   string
	pass   string
	hash   string
	timing core.TimingConfig
}

func New(target core.HostRef, domain, user, pass, hash string, opts ...Option) *LocalTransport {
	lt := &LocalTransport{
		domain: domain,
		user:   user,
		pass:   pass,
		hash:   hash,
		timing: core.DefaultTiming(),
	}
	for _, opt := range opts {
		opt(lt)
	}
	return lt
}

func (t *LocalTransport) nxcTarget(protocol string, target core.HostRef) tools.NetExecTarget {
	return tools.NetExecTarget{
		Protocol: protocol,
		Host:     target.Name,
		Domain:   t.domain,
		Username: t.user,
		Password: t.pass,
		Hash:     t.hash,
	}
}

func (t *LocalTransport) Exec(ctx context.Context, target core.HostRef, command string, timeout time.Duration) core.ExecResult {
	if t.timing.DelayMs > 0 {
		time.Sleep(t.timing.Delay())
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	nt := t.nxcTarget("smb", target)
	r, err := tools.NetExec.RunFailover(ctx, nt, command, timeout)
	res := core.ExecResult{
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		ExitCode: r.ExitCode,
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

func (t *LocalTransport) Upload(ctx context.Context, target core.HostRef, data []byte, remoteDir, remoteName string) (string, error) {
	if t.timing.DelayMs > 0 {
		time.Sleep(t.timing.Delay())
	}
	tmpDir, err := os.MkdirTemp("", "adpack-upload-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	localPath := filepath.Join(tmpDir, remoteName)
	if err := os.WriteFile(localPath, data, 0644); err != nil {
		return "", fmt.Errorf("write temp file: %w", err)
	}

	nt := t.nxcTarget("smb", target)
	r, err := tools.NetExec.PutFile(ctx, nt, localPath, remoteDir)
	if err != nil || !r.Success {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		return "", fmt.Errorf("upload failed: %s (stderr=%s)", errStr, r.Stderr)
	}

	remotePath := strings.TrimRight(remoteDir, `\`)
	remotePath += `\` + remoteName
	return remotePath, nil
}

func (t *LocalTransport) Download(ctx context.Context, target core.HostRef, remotePath string) ([]byte, error) {
	if t.timing.DelayMs > 0 {
		time.Sleep(t.timing.Delay())
	}
	tmpDir, err := os.MkdirTemp("", "adpack-download-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cleanRemote := strings.ReplaceAll(remotePath, `\`, `/`)
	localName := filepath.Base(cleanRemote)
	if localName == "." || localName == "/" {
		return nil, fmt.Errorf("download: invalid remote path %q", remotePath)
	}
	localPath := filepath.Join(tmpDir, localName)

	nt := t.nxcTarget("smb", target)
	_, err = tools.NetExec.GetFile(ctx, nt, remotePath, localPath)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}

	data, readErr := os.ReadFile(localPath)
	if readErr != nil {
		return nil, fmt.Errorf("read downloaded file: %w", readErr)
	}
	return data, nil
}

func (t *LocalTransport) Type() string {
	return "local"
}
