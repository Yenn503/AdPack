package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"adpack/core"
	"adpack/modules"
	"adpack/utils"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
)

var (
	evasionProfile string
	targetHost     string
	executePaths   bool
	dryRun         bool
	resume         bool
)

var runCmd = &cobra.Command{
	Use:   "run [phase]",
	Short: "Execute a specific attack phase",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		phase := core.Phase(args[0])
		valid := false
		for _, p := range core.AllPhases {
			if p == phase {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown phase: %s\nValid phases: %s", phase, strings.Join(phaseNames(), ", "))
		}

		if evasionProfile == "" {
			evasionProfile = "native"
			if Cfg != nil && Cfg.Profile != "" {
				evasionProfile = Cfg.Profile
			}
		}

		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}

		// Scope enforcement
		if len(Cfg.Scope) > 0 {
			scope, err := core.NewScope(Cfg.Scope)
			if err != nil {
				return fmt.Errorf("invalid scope: %w", err)
			}
			if targetHost != "" && !scope.Contains(targetHost) {
				return fmt.Errorf("target %s is outside allowed scope %s", targetHost, scope)
			}
			fmt.Printf("  [Scope] %s\n\n", scope)
		}

		// Dry-run mode
		if dryRun {
			plan := core.DryRun(phase, state)
			fmt.Printf("  Dry-run for phase %s:\n", phase)
			for _, a := range plan.Actions {
				fmt.Printf("    • %s\n", a)
			}
			if plan.Destructive {
				fmt.Printf("\n  ⚠  DESTRUCTIVE: %s (use --confirm to execute)\n", phase)
			}
			return nil
		}

		// Provider event logging
		sink := core.ProviderEventSink(core.NoopSink{})
		if providerLogPath != "" {
			f, fErr := os.Create(providerLogPath)
			if fErr != nil {
				return fmt.Errorf("create provider log: %w", fErr)
			}
			defer f.Close()
			sink = core.NewJSONLSink(f)
		}

		// Phase header
		printPhaseHeader(phase, state)

		// Resume: restore phase execution tracking
		if resume {
			exec, ok := state.PhaseExecutions[phase]
			if ok && exec.Complete {
				fmt.Printf("  [Resume] Phase %s already complete, skipping\n", phase)
				return nil
			}
			if ok {
				pending := exec.PendingHosts()
				if len(pending) > 0 {
					fmt.Printf("  [Resume] Re-running %d failed/pending hosts\n", len(pending))
				}
				done := exec.SkippedHosts()
				if len(done) > 0 {
					fmt.Printf("  [Resume] Skipping %d already-processed hosts\n", len(done))
				}
			}
		}

		// Initialize phase execution tracker
		if state.PhaseExecutions == nil {
			state.PhaseExecutions = make(map[core.Phase]*core.PhaseExecution)
		}
		if _, exists := state.PhaseExecutions[phase]; !exists {
			state.PhaseExecutions[phase] = core.NewPhaseExecution(phase)
		}
		exec := state.PhaseExecutions[phase]

		// Mark all hosts pending for this phase
		for _, h := range state.Hosts {
			if _, tracked := exec.Hosts[h.IP]; !tracked {
				exec.Hosts[h.IP] = core.HostPending
			}
		}

		state.Phases[phase] = core.PhaseInProgress
		if err := DB.SavePhases(state); err != nil {
			return fmt.Errorf("save phases: %w", err)
		}

		var success bool
		start := time.Now()

		switch phase {
		case core.PhaseDiscovery:
			result := modules.RunDiscovery(state, targetHost, Cfg.Scope)
			success = result.Success
			if result.Success {
				for _, h := range result.Hosts {
					if resume && exec.Hosts[h.IP] == core.HostDone {
						continue
					}
					DB.SaveHost(h)
					exec.MarkDone(h.IP)
				}
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				printResult("Hosts discovered", len(result.Hosts))
				for _, h := range result.Hosts {
					printHostRow(h)
				}
			}

		case core.PhaseEnumeration:
			result := modules.RunEnumeration(state, targetHost)
			success = result.Success
			if result.Success {
				for _, u := range result.Users {
					DB.SaveUser(u)
				}
				for _, c := range result.Creds {
					DB.SaveCred(c)
				}
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				if targetHost != "" {
					exec.MarkDone(targetHost)
				}
				printResult("Users enumerated", len(result.Users))
				if len(result.Creds) > 0 {
					printResult("Credentials found in descriptions", len(result.Creds))
				}
			}

		case core.PhaseCredentialAcq:
			result := modules.RunCredentialAcq(state, evasionProfile, targetHost)
			success = result.Success
			for _, ev := range result.Evidence {
				DB.SaveEvidence(ev)
			}
			if result.Success {
				for _, c := range result.Creds {
					DB.SaveCred(c)
				}
				if targetHost != "" {
					exec.MarkDone(targetHost)
				}
				printResult("Credentials acquired", len(result.Creds))
				for _, c := range result.Creds {
					printCredRow(c)
				}
			} else {
				fmt.Println(utils.ErrorStyle.Render("  ✗  Credential acquisition failed"))
				for _, ev := range result.Evidence {
					if ev.Key == "error" {
						fmt.Printf("    %s  %s\n", utils.ErrorStyle.Render("→"), ev.Value)
					}
				}
				if targetHost != "" {
					exec.MarkFailed(targetHost)
				}
			}

		case core.PhaseValidation:
			result := modules.RunValidation(state, targetHost)
			success = result.Success
			for _, ev := range result.Evidence {
				DB.SaveEvidence(ev)
			}
			if targetHost != "" {
				if success {
					exec.MarkDone(targetHost)
				} else {
					exec.MarkFailed(targetHost)
				}
			}
			if err := DB.SaveState(state); err != nil {
				return fmt.Errorf("save state: %w", err)
			}

		case core.PhaseSessionHarvest:
			provider, pErr := modules.ProviderFromState(state, targetHost, sink)
			if pErr != nil {
				fmt.Printf("[!] %v\n", pErr)
				success = false
				break
			}
			result := modules.RunSessionHarvest(context.Background(), provider, state)
			success = result.Success
			if result.Success {
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				DB.SaveSessions(result.Sessions)
				state.Sessions = result.Sessions
				if targetHost != "" {
					exec.MarkDone(targetHost)
				}
				printResult("Sessions harvested", len(result.Sessions))
			}

		case core.PhaseGraphAnalysis:
			provider, pErr := modules.ProviderFromState(state, targetHost, sink)
			if pErr != nil {
				fmt.Printf("[!] %v\n", pErr)
				success = false
				break
			}
			result := modules.RunGraphAnalysis(context.Background(), provider)
			success = result.Success
			if result.Success {
				for _, c := range result.Computers {
					DB.SaveComputer(c)
				}
				for _, g := range result.GPOs {
					DB.SaveGPO(g)
				}
				for _, t := range result.ADCS {
					DB.SaveADCSTemplate(t)
				}
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				for _, u := range result.Users {
					DB.SaveUser(u)
				}
				if targetHost != "" {
					exec.MarkDone(targetHost)
				}
				printResult("Computers found", len(result.Computers))
				printResult("GPOs found", len(result.GPOs))
				printResult("ADCS templates found", len(result.ADCS))
			}

		case core.PhaseLateral:
			result := modules.RunLateral(state, targetHost)
			success = result.Success
			if result.Success {
				for _, h := range result.Hosts {
					if resume && exec.Hosts[h.IP] == core.HostDone {
						continue
					}
					DB.SaveHost(h)
					exec.MarkDone(h.IP)
				}
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
			}

		case core.PhasePrivEsc:
			result := modules.RunPrivesc(state, targetHost, evasionProfile, executePaths)
			success = result.Success
			if result.Success {
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				if targetHost != "" {
					exec.MarkDone(targetHost)
				}
				printResult("Privesc checks completed", 0)
			}

		case core.PhasePersistence:
			result := modules.RunPersistence(state, targetHost)
			success = result.Success
			if result.Success {
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				if targetHost != "" {
					exec.MarkDone(targetHost)
				}
				printResult("Persistence mechanisms deployed", 0)
			}

		case core.PhaseImpact:
			result := modules.RunImpact(state, evasionProfile)
			success = result.Success
			for _, ev := range result.Evidence {
				DB.SaveEvidence(ev)
			}

		case core.PhaseHybridBridge:
			result := modules.RunHybridBridge(state)
			success = result.Success
			for _, ev := range result.Evidence {
				DB.SaveEvidence(ev)
			}

		case core.PhaseCloudInitialAccess:
			utils.PhaseSkipped(string(phase), "cloud initial access is interactive", "adpack initial <teams|device-code|consent-phish>")
			state.Phases[phase] = core.PhaseSkipped

		case core.PhaseCloudEnum:
			utils.PhaseSkipped(string(phase), "cloud phases run through the cloud command surface", "adpack cloud enum")
			state.Phases[phase] = core.PhaseSkipped

		case core.PhaseCloudCredAcq:
			utils.PhaseSkipped(string(phase), "cloud phases run through the cloud command surface", "adpack cloud cred-acq")
			state.Phases[phase] = core.PhaseSkipped

		case core.PhaseCloudPrivesc:
			utils.PhaseSkipped(string(phase), "cloud phases run through the cloud command surface", "adpack cloud privesc")
			state.Phases[phase] = core.PhaseSkipped

		case core.PhaseCloudPillage:
			utils.PhaseSkipped(string(phase), "cloud phases run through the cloud command surface", "adpack cloud pillage")
			state.Phases[phase] = core.PhaseSkipped

		default:
			return fmt.Errorf("phase %q has no implementation", phase)
		}

		// Update phase execution tracking
		elapsed := time.Since(start).Round(time.Millisecond)
		if success {
			exec.Complete = true
			state.Phases[phase] = core.PhaseComplete
		} else {
			state.Phases[phase] = core.PhaseUntouched
		}
		DB.SavePhases(state)

		// Footer
		fmt.Println()
		if success {
			utils.PhaseComplete(elapsed)
		} else {
			utils.PhaseFailed(elapsed)
		}

		// Show what's next
		state, _ = DB.LoadState()
		next := state.NextPhase()
		if next != nil {
			var runHint string
			switch *next {
			case core.PhaseCloudInitialAccess:
				runHint = "adpack initial <teams|device-code|consent-phish>"
			case core.PhaseCloudEnum:
				runHint = "adpack cloud enum"
			case core.PhaseCloudCredAcq:
				runHint = "adpack cloud cred-acq"
			case core.PhaseCloudPrivesc:
				runHint = "adpack cloud privesc"
			case core.PhaseCloudPillage:
				runHint = "adpack cloud pillage"
			default:
				runHint = "adpack run " + string(*next)
			}
			fmt.Printf("\n  %s  %s\n",
				lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("Next:"),
				runHint)
		}

		return nil
	},
}

func printPhaseHeader(phase core.Phase, state *core.ADState) {
	rationale := phaseRationale(phase, state)
	stats := phaseStats(phase, state)
	combined := rationale
	if stats != "" {
		if combined != "" {
			combined += "  |  "
		}
		combined += stats
	}
	utils.PhaseHeader(1, string(phase), combined)
}

func phaseRationale(phase core.Phase, _ *core.ADState) string {
	switch phase {
	case core.PhaseDiscovery:
		return "Network sweep and port scan to identify domain-joined systems"
	case core.PhaseEnumeration:
		return "LDAP enumeration of users, groups, computers, and AD objects"
	case core.PhaseCredentialAcq:
		return "Credential dumping via minidump, DCSync, SAM, and DPAPI"
	case core.PhaseValidation:
		return "Verify acquired credentials against domain controllers"
	case core.PhaseSessionHarvest:
		return "Enumerate active user logon sessions for lateral movement targets"
	case core.PhaseGraphAnalysis:
		return "BloodHound collection and privilege path analysis"
	case core.PhasePrivEsc:
		return "Escalate privileges via ACL abuse, RBCD, ADCS, or Kerberos attacks"
	case core.PhaseLateral:
		return "Credential-driven lateral movement using WMI, WinRM, PsExec, or SMB"
	case core.PhasePersistence:
		return "Deploy persistence: scheduled tasks, DSRM, golden/silver tickets"
	case core.PhaseImpact:
		return "Execute mission objectives — exfil, ransom, or destroy"
	case core.PhaseHybridBridge:
		return "Map on-prem to cloud identity bridge and federation trust"
	case core.PhaseCloudInitialAccess:
		return "Entra ID initial access via device code or consent phish"
	case core.PhaseCloudEnum:
		return "Enumerate Entra ID tenant structure and security posture"
	case core.PhaseCloudCredAcq:
		return "Acquire cloud credentials via password spray or token theft"
	case core.PhaseCloudPrivesc:
		return "Escalate cloud roles: Global Admin, Privileged Role Admin"
	case core.PhaseCloudPillage:
		return "Exfiltrate mail, SharePoint, OneDrive, and Teams data"
	}
	return ""
}

func phaseStats(phase core.Phase, state *core.ADState) string {
	hosts := len(state.Hosts)
	creds := len(state.Creds)
	users := len(state.Users)
	comps := len(state.Computers)
	groups := len(state.Groups)
	var parts []string
	switch phase {
	case core.PhaseDiscovery:
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts known", hosts))
		}
	case core.PhaseEnumeration:
		if users > 0 {
			parts = append(parts, fmt.Sprintf("%d users", users))
		}
		if comps > 0 {
			parts = append(parts, fmt.Sprintf("%d computers", comps))
		}
		if groups > 0 {
			parts = append(parts, fmt.Sprintf("%d groups", groups))
		}
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts", hosts))
		}
	case core.PhaseCredentialAcq:
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials held", creds))
		}
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts", hosts))
		}
	case core.PhaseValidation:
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials to verify", creds))
		}
	case core.PhaseSessionHarvest:
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts", hosts))
		}
	case core.PhaseGraphAnalysis:
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts", hosts))
		}
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials", creds))
		}
	case core.PhasePrivEsc:
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials", creds))
		}
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts", hosts))
		}
	case core.PhaseLateral:
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials", creds))
		}
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts", hosts))
		}
	case core.PhasePersistence:
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials", creds))
		}
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d DCs accounted", countDC(state)))
		}
	case core.PhaseImpact:
		if hosts > 0 {
			parts = append(parts, fmt.Sprintf("%d hosts in scope", hosts))
		}
		if creds > 0 {
			parts = append(parts, fmt.Sprintf("%d credentials", creds))
		}
	}
	return strings.Join(parts, ", ")
}

func countDC(state *core.ADState) int {
	n := 0
	for _, h := range state.Hosts {
		if h.IsDC {
			n++
		}
	}
	return n
}

func printResult(label string, count int) {
	fmt.Printf("  %s  %s  %s\n",
		utils.SuccessStyle.Render("✓"),
		label+":",
		lipgloss.NewStyle().Bold(true).Foreground(utils.ColorHighlight).Render(fmt.Sprintf("%d", count)))
}

func printHostRow(h core.Host) {
	dc := ""
	if h.IsDC {
		dc = utils.WarningStyle.Render(" [DC]")
	}
	fmt.Printf("    %s  %s%s  %s\n",
		lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
		h.IP, dc, lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(h.Domain))
}

func printCredRow(c core.Credential) {
	secret := ""
	if c.Secret != "" {
		secret = "  " + lipgloss.NewStyle().Foreground(utils.ColorWarning).Render(c.Secret)
	}
	if c.Hash != "" {
		secret += "  " + lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("[NTLM:"+c.Hash[:min(8, len(c.Hash))]+"...]")
	}
	fmt.Printf("    %s  %s\\%s%s\n",
		lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
		c.Domain, c.Username, secret)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func phaseNames() []string {
	names := make([]string, len(core.AllPhases))
	for i, p := range core.AllPhases {
		names[i] = string(p)
	}
	return names
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&evasionProfile, "evasion-profile", "e", "",
		"Evasion profile (native|pplshade|phantomkiller)")
	runCmd.Flags().StringVarP(&targetHost, "target", "t", "",
		"Target host IP or hostname")
	runCmd.Flags().StringVar(&providerLogPath, "provider-log", "", "Write provider acquisition events as JSONL to this path")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without executing")
	runCmd.Flags().BoolVar(&resume, "resume", false, "Resume phase execution, skipping completed hosts")
	runCmd.Flags().BoolVarP(&executePaths, "execute", "x", false, "Execute planned privilege escalation paths")
	runCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return phaseNames(), cobra.ShellCompDirectiveNoFileComp
	}
}
