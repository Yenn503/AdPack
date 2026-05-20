package tools

import (
	"context"
	"fmt"
	"strings"

	"adpack/utils"
)

type ldapsearchTool struct{}

var Ldapsearch ldapsearchTool

type LdapsearchConfig struct {
	Host     string
	Domain   string
	Username string
	Password string
}

func (l ldapsearchTool) QueryGPOs(ctx context.Context, cfg LdapsearchConfig) (utils.CmdResult, error) {
	parts := strings.Split(cfg.Domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	baseDN := "CN=Policies,CN=System," + strings.Join(dcs, ",")
	bindDN := cfg.Username + "@" + cfg.Domain

	args := []string{
		"-H", "ldap://" + cfg.Host,
		"-D", bindDN,
		"-w", cfg.Password,
		"-b", baseDN,
		"-s", "one",
		"-o", "ldif-wrap=no",
		"(objectClass=groupPolicyContainer)",
		"dn", "cn", "displayName", "gPCFileSysPath",
	}

	r := utils.RunCommandCtx(ctx, "ldapsearch", args)
	if !r.Success {
		return r, fmt.Errorf("ldapsearch failed: %s", r.Stderr)
	}
	return r, nil
}
