package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type tokenTacticsTool struct{}

var TokenTactics = tokenTacticsTool{}

func (tokenTacticsTool) Name() string { return "TokenTactics" }

func (tokenTacticsTool) Available() bool {
	_, err := exec.LookPath("roadtx")
	return err == nil
}

func (t tokenTacticsTool) RunDeviceCodeAuth(ctx context.Context, clientID, tenantID string) (utils.CmdResult, error) {
	if tenantID == "" {
		tenantID = "organizations"
	}
	args := []string{"deviceauth", "-c", clientID, "-t", tenantID, "--timeout", "120"}
	cr := utils.RunCommandCtx(ctx, "roadtx", args)
	if !cr.Success {
		return cr, fmt.Errorf("roadtx deviceauth failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (t tokenTacticsTool) RunRefreshToken(ctx context.Context, refreshToken, clientID string) (utils.CmdResult, error) {
	cr := utils.RunCommandCtx(ctx, "roadtx", []string{"gettoken", "-c", clientID, "-r", refreshToken})
	if !cr.Success {
		return cr, fmt.Errorf("roadtx refresh token failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (t tokenTacticsTool) RunTokenToList(ctx context.Context, accessToken string) (utils.CmdResult, error) {
	cr := utils.RunCommandCtx(ctx, "roadtx", []string{"decode", accessToken})
	if !cr.Success {
		return cr, fmt.Errorf("roadtx decode token failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (t tokenTacticsTool) RunTokenToPRT(ctx context.Context, refreshToken, clientID string) (utils.CmdResult, error) {
	cr := utils.RunCommandCtx(ctx, "roadtx", []string{"gettoken", "-c", clientID, "-r", refreshToken, "-s", "https://login.microsoftonline.com/common/userrealm/"})
	if !cr.Success {
		return cr, fmt.Errorf("roadtx PRT failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (t tokenTacticsTool) RunTokenToSessionKey(ctx context.Context, refreshToken, clientID string) (utils.CmdResult, error) {
	cr := utils.RunCommandCtx(ctx, "roadtx", []string{"sessionkey", "-r", refreshToken, "-c", clientID})
	if !cr.Success {
		return cr, fmt.Errorf("roadtx session key failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (t tokenTacticsTool) RunTokenToAccessToken(ctx context.Context, refreshToken, clientID, resource string) (utils.CmdResult, error) {
	resourceMap := map[string]string{
		"graph":      "https://graph.microsoft.com",
		"azure":      "https://management.azure.com",
		"outlook":    "https://outlook.office.com",
		"sharepoint": "https://sharepoint.com",
	}
	target, ok := resourceMap[strings.ToLower(resource)]
	if !ok {
		target = resource
	}
	cr := utils.RunCommandCtx(ctx, "roadtx", []string{"gettoken", "-c", clientID, "-r", refreshToken, "-s", target})
	if !cr.Success {
		return cr, fmt.Errorf("roadtx access token failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (t tokenTacticsTool) RunTokenToPRTWithSessionKey(ctx context.Context, refreshToken, clientID, sessionKey string) (utils.CmdResult, error) {
	cr := utils.RunCommandCtx(ctx, "roadtx", []string{"gettoken", "-c", clientID, "-r", refreshToken, "-s", "https://login.microsoftonline.com/common/userrealm/", "-k", sessionKey})
	if !cr.Success {
		return cr, fmt.Errorf("roadtx PRT with session key failed: %s", cr.Stderr)
	}
	return cr, nil
}
