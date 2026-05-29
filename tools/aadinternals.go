package tools

import (
	"adpack/utils"
	"context"
	"fmt"
)

type aadInternalsTool struct{}

var AADInternals = aadInternalsTool{}

func (aadInternalsTool) Name() string { return "AADInternals" }

func (aadInternalsTool) Available() bool { return utils.PSModuleInstalled("AADInternals") }

func (a aadInternalsTool) runPS(ctx context.Context, command string) (utils.CmdResult, error) {
	encoded := utils.EncodePowerShell(fmt.Sprintf(`Import-Module "AADInternals" -Force; %s`, command))
	cr := utils.RunCommandCtx(ctx, "pwsh", []string{"-NoP", "-NonI", "-EncodedCommand", encoded})
	if !cr.Success {
		return cr, fmt.Errorf("aadinternals command failed: %s", cr.Stderr)
	}
	return cr, nil
}

func (a aadInternalsTool) runPSWithCreds(ctx context.Context, command, username, password string) (utils.CmdResult, error) {
	cmd := fmt.Sprintf(command, username, password)
	return a.runPS(ctx, cmd)
}

func (a aadInternalsTool) RunTenantEnum(ctx context.Context, username, password string) (utils.CmdResult, error) {
	return a.runPSWithCreds(ctx,
		`Get-AADIntUsers -UserName "%s" -Password "%s" | ConvertTo-Json -Depth 10`,
		username, password)
}

func (a aadInternalsTool) RunSPEnum(ctx context.Context, username, password string) (utils.CmdResult, error) {
	return a.runPSWithCreds(ctx,
		`Get-AADIntServicePrincipals -UserName "%s" -Password "%s" | ConvertTo-Json`,
		username, password)
}

func (a aadInternalsTool) RunAADConnectExtract(ctx context.Context) (utils.CmdResult, error) {
	return a.runPS(ctx, "Get-AADIntAzureADConnectCredentials | ConvertTo-Json")
}

func (a aadInternalsTool) RunADFSCertExtract(ctx context.Context) (utils.CmdResult, error) {
	return a.runPS(ctx, "Convert-AADIntADFSTokenSigningCertificateToX509 | ConvertTo-Json")
}

func (a aadInternalsTool) RunCAPEnum(ctx context.Context, username, password string) (utils.CmdResult, error) {
	return a.runPSWithCreds(ctx,
		`Get-AADIntConditionalAccessPolicies -UserName "%s" -Password "%s" | ConvertTo-Json`,
		username, password)
}
