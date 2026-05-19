package tools

import (
	"context"
	"fmt"
	"strings"

	"adpack/core"
	"adpack/utils"
)

type nxcTool struct{}

var NetExec = nxcTool{}

func (nxcTool) Name() string { return "netexec" }
func (nxcTool) Available() bool {
	_, err := utils.FindTool("netexec")
	return err == nil
}

type NetExecTarget struct {
	Protocol string // smb, ldap, winrm, mssql
	Host     string
	Port     int
	Domain   string
	Username string
	Password string
	Hash     string
}

func (n nxcTool) Run(ctx context.Context, target NetExecTarget, subcmd string, extraArgs []string) (utils.CmdResult, error) {
	args := []string{target.Protocol, target.Host}
	if target.Port > 0 {
		args = append(args, fmt.Sprintf("--port=%d", target.Port))
	}
	if target.Domain != "" {
		args = append(args, "-d", target.Domain)
	}
	if target.Username != "" {
		args = append(args, "-u", target.Username)
	}
	if target.Password != "" {
		args = append(args, "-p", target.Password)
	}
	if target.Hash != "" {
		args = append(args, "-H", target.Hash)
	}
	if subcmd != "" {
		args = append(args, subcmd)
	}
	args = append(args, extraArgs...)
	r := utils.RunCommandCtx(ctx, "netexec", args)
	if !r.Success {
		return r, fmt.Errorf("netexec failed: %s", r.Stderr)
	}
	return r, nil
}

func (n nxcTool) AuthTest(ctx context.Context, target NetExecTarget) bool {
	_, err := n.Run(ctx, target, "", nil)
	return err == nil
}

func (n nxcTool) EnumUsers(ctx context.Context, target string) ([]core.User, error) {
	r := utils.RunCommandCtx(ctx, "netexec", []string{"ldap", target, "--users"})
	if !r.Success {
		return nil, fmt.Errorf("netexec ldap enum failed: %s", r.Stderr)
	}
	var users []core.User
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.Contains(line, "USER:") {
			parts := strings.Split(line, "USER:")
			if len(parts) > 1 {
				username := strings.TrimSpace(strings.Split(parts[1], " ")[0])
				if username != "" {
					users = append(users, core.User{Username: username, Source: "netexec"})
				}
			}
		}
	}
	return users, nil
}

func (n nxcTool) EnumShares(ctx context.Context, target NetExecTarget) ([]string, error) {
	r, err := n.Run(ctx, target, "--shares", nil)
	if err != nil { return nil, err }
	var shares []string
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.Contains(line, "SHARE:") {
			parts := strings.Split(line, "SHARE:")
			if len(parts) > 1 {
				shares = append(shares, strings.TrimSpace(strings.Split(parts[1], " ")[0]))
			}
		}
	}
	return shares, nil
}

func (n nxcTool) PutFile(ctx context.Context, target NetExecTarget, localPath, remoteDir string) (utils.CmdResult, error) {
	return n.Run(ctx, target, "--put-file", []string{localPath, remoteDir})
}

func (n nxcTool) GetFile(ctx context.Context, target NetExecTarget, remotePath, localDir string) (utils.CmdResult, error) {
	return n.Run(ctx, target, "--get-file", []string{remotePath, localDir})
}
