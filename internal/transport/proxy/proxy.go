package proxy

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"adpack/core"
	"adpack/internal/transport/local"
	"adpack/tools"
)

type ProxyTransport struct {
	local     *local.LocalTransport
	proxyAddr string
	proxied   bool
}

func New(target core.HostRef, domain, user, pass, hash string, proxyAddr string) *ProxyTransport {
	proxied := false
	if _, err := exec.LookPath("proxychains4"); err == nil {
		tools.SetProxyMode(proxyAddr)
		fmt.Printf("[*] Proxy transport enabled: proxychains4 \u2192 %s\n", proxyAddr)
		proxied = true
	} else {
		fmt.Println("[!] proxychains4 not found, traffic will NOT be proxied")
	}
	return &ProxyTransport{
		local:     local.New(target, domain, user, pass, hash),
		proxyAddr: proxyAddr,
		proxied:   proxied,
	}
}

func (t *ProxyTransport) Exec(ctx context.Context, target core.HostRef, command string, timeout time.Duration) core.ExecResult {
	return t.local.Exec(ctx, target, command, timeout)
}

func (t *ProxyTransport) Upload(ctx context.Context, target core.HostRef, data []byte, remoteDir, remoteName string) (string, error) {
	return t.local.Upload(ctx, target, data, remoteDir, remoteName)
}

func (t *ProxyTransport) Download(ctx context.Context, target core.HostRef, remotePath string) ([]byte, error) {
	return t.local.Download(ctx, target, remotePath)
}

func (t *ProxyTransport) Type() string {
	return fmt.Sprintf("proxy(%s)", t.proxyAddr)
}
