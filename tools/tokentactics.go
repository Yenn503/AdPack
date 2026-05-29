package tools

import (
	"adpack/utils"
	"context"
	"encoding/json"
	"fmt"
)

type tokenTacticsTool struct{}

var TokenTactics = tokenTacticsTool{}

type AzureToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Resource     string `json:"resource"`
	ClientID     string `json:"client_id"`
}

func (tokenTacticsTool) Name() string { return "TokenTactics" }

func (tokenTacticsTool) Available() bool { return utils.PSModuleInstalled("TokenTactics") }

func (tokenTacticsTool) RunDeviceCodeAuth(ctx context.Context, client string) (string, error) {
	cmd := fmt.Sprintf("Get-AzureToken -Client %s", client)
	result, err := utils.RunPSModule(ctx, "TokenTactics", cmd, nil)
	if err != nil {
		return "", fmt.Errorf("token tactics device code auth failed: %w", err)
	}
	return result.Stdout, nil
}

var tokenTacticsRefreshCmd = map[string]string{
	"MSGraph":         "Invoke-RefreshToMSGraphToken",
	"Outlook":         "Invoke-RefreshToOutlookToken",
	"AzureManagement": "Invoke-RefreshToAzureManagementToken",
}

func (tokenTacticsTool) RunRefreshToken(ctx context.Context, domain, refreshToken, resource string) (*AzureToken, error) {
	cmdName, ok := tokenTacticsRefreshCmd[resource]
	if !ok {
		return nil, fmt.Errorf("unknown resource: %s", resource)
	}
	cmd := fmt.Sprintf(`%s -domain "%s" -refreshToken "%s" | ConvertTo-Json`, cmdName, domain, refreshToken)
	result, err := utils.RunPSModule(ctx, "TokenTactics", cmd, nil)
	if err != nil {
		return nil, fmt.Errorf("token tactics refresh failed: %w", err)
	}
	var token AzureToken
	if err := json.Unmarshal([]byte(result.Stdout), &token); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	return &token, nil
}

func (tokenTacticsTool) ClearTokens(ctx context.Context) error {
	_, err := utils.RunPSModule(ctx, "TokenTactics", "Invoke-ClearToken -Token All", nil)
	if err != nil {
		return fmt.Errorf("token tactics clear tokens failed: %w", err)
	}
	return nil
}
