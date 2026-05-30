package modules

import (
	"log/slog"
	"strings"

	"adpack/core"
)

func RunHybridBridge(state *core.ADState) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping hybrid bridge")
		return result
	}

	slog.Info("hybrid bridge: probing on-prem to cloud convergence paths")

	hasAADConnect := false
	hasSeamlessSSO := false
	hasFederation := false

	for _, r := range state.CloudResources {
		props := strings.ToLower(r.Properties)
		if r.Type == "service_principal" && strings.Contains(props, "aad connect") {
			hasAADConnect = true
		}
		if r.Type == "service_principal" && strings.Contains(props, "seamless sso") {
			hasSeamlessSSO = true
		}
		if r.Type == "domain" && strings.Contains(props, "federated") {
			hasFederation = true
		}
	}

	if hasAADConnect {
		slog.Warn("hybrid bridge: AAD Connect detected — extract MSOL_/Sync_ credentials for cloud GA")
	}
	if hasSeamlessSSO {
		slog.Warn("hybrid bridge: Seamless SSO enabled — forge AZUREADSSOACC$ Kerberos tickets")
	}
	if hasFederation {
		slog.Warn("hybrid bridge: federated domain detected — Golden SAML possible")
	}

	slog.Info("hybrid bridge: convergence paths evaluated",
		"aadconnect", hasAADConnect,
		"seamless_sso", hasSeamlessSSO,
		"federation", hasFederation,
	)

	slog.Info("hybrid bridge phase complete")
	return result
}
