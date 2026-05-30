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
	maxPhases       int
	skipFail        bool
	seedDomain      string
	seedUser        string
	seedPass        string
	providerLogPath string
)

var autoRunCmd = &cobra.Command{
	Use:   "autorun",
	Short: "Automatically execute the full attack chain in sequence",
	Long: `Evaluates current state, determines the next recommended phase, executes it,
saves results, and repeats until the chain is complete or a phase fails.

Use --max to limit the number of phases executed. By default, autorun continues
past failed phases. Use --skip-fail=false to stop on failures.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var state *core.ADState
		var err error

		// ── Banner ────────────────────────────────────────────────────────
		fmt.Println()
		bar := strings.Repeat("─", 52)
		fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))
		fmt.Printf("  %s\n", lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary).Render("AUTO-RUN  ·  Automated Attack Chain"))
		if targetHost != "" {
			fmt.Printf("  %s  %s\n", lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("Target:"), targetHost)
		}
		if maxPhases > 0 {
			fmt.Printf("  %s  %d phases\n", lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("Limit: "), maxPhases)
		}
		fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))
		fmt.Println()

		// Provider event logging
		sink := core.ProviderEventSink(core.NoopSink{})
		if providerLogPath != "" {
			f, fErr := os.Create(providerLogPath)
			if fErr != nil {
				return fmt.Errorf("create provider log: %w", fErr)
			}
			defer f.Close()
			sink = core.NewJSONLSink(f)
			fmt.Printf("  %s  Provider events → %s\n",
				utils.InfoStyle.Render("→"), providerLogPath)
		}

		// Evasion profile: CLI flag > config profile > default
		if evasionProfile == "" {
			evasionProfile = "native"
			if Cfg != nil && Cfg.Profile != "" {
				evasionProfile = Cfg.Profile
			}
		}

		// Seed initial credentials: CLI flags > config seeds > config domain
		if seedDomain == "" && Cfg != nil {
			seedDomain = Cfg.Domain
		}
		if seedUser == "" && seedPass == "" && Cfg != nil && len(Cfg.Seeds) > 0 {
			s := Cfg.Seeds[0]
			seedUser = s.User
			seedPass = s.Password
			if seedDomain == "" {
				seedDomain = s.Domain
			}
		}
		if seedDomain != "" && seedUser != "" && seedPass != "" {
			dbCreds, _ := DB.LoadCreds()
			alreadySeeded := false
			for _, c := range dbCreds {
				if c.Domain == seedDomain && c.Username == seedUser {
					alreadySeeded = true
					break
				}
			}
			if !alreadySeeded {
				DB.SaveCred(core.Credential{
					Type: core.CredPlaintext, Username: seedUser,
					Domain: seedDomain, Secret: seedPass,
					Source: "manual_seed", Validated: true,
				})
				fmt.Printf("  %s  Seeded creds: %s\\%s\n",
					utils.InfoStyle.Render("→"), seedDomain, seedUser)
			}
		}

		phasesRun := 0
		var credsAtLastRun int
		credAcqReruns := 0

		for {
			if maxPhases > 0 && phasesRun >= maxPhases {
				utils.LimitReached(maxPhases)
				break
			}

			// Reload state so engine sees latest DB
			state, err = DB.LoadState()
			if err != nil {
				return fmt.Errorf("reload state: %w", err)
			}
			// Clean up bogus artifact users/creds on every reload
			state = modules.FilterBogusState(state)
			if phasesRun == 0 {
				credsAtLastRun = len(state.Creds)
			}
			engine := core.NewEngine(state)

			rec := engine.Evaluate()
			if rec.Phase == "" {
				utils.AllComplete()
				break
			}

			// Phase header
			utils.PhaseHeader(phasesRun+1, string(rec.Phase), rec.Rationale)

			state.Phases[rec.Phase] = core.PhaseInProgress
			DB.SavePhases(state)

			success := false
			start := time.Now()

			switch rec.Phase {
			case core.PhaseDiscovery:
				result := modules.RunDiscovery(state, targetHost, Cfg.Scope)
				if result.Success {
					for _, h := range result.Hosts {
						DB.SaveHost(h)
					}
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					success = true
					utils.StepOk(fmt.Sprintf("%d host(s) discovered", len(result.Hosts)))
					for _, h := range result.Hosts {
						dc := ""
						if h.IsDC {
							dc = utils.WarningStyle.Render(" [DC]")
						}
						utils.Finding(h.IP, dc)
					}
				}

			case core.PhaseEnumeration:
				result := modules.RunEnumeration(state, targetHost)
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
					success = true
					utils.StepOk(fmt.Sprintf("%d user(s) enumerated", len(result.Users)))
					if len(result.Creds) > 0 {
						utils.StepOk(fmt.Sprintf("%d credential(s) found in descriptions", len(result.Creds)))
					}
				}

			case core.PhaseCredentialAcq:
				var kr *core.ToolResult
				if credAcqReruns == 0 {
					utils.Step("Kerberos pre-check...")
					kr = modules.RunKerberos(state, targetHost)
					for _, u := range kr.Users {
						DB.SaveUser(u)
					}
					for _, c := range kr.Creds {
						DB.SaveCred(c)
					}
					for _, ev := range kr.Evidence {
						DB.SaveEvidence(ev)
					}
				} else {
					kr = &core.ToolResult{}
				}

				// Spray: runs every time (non-privileged, finds weak/default creds)
				result := modules.RunCredentialAcq(state, evasionProfile, targetHost)
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				for _, c := range result.Creds {
					DB.SaveCred(c)
				}
				if result.Success || len(kr.Creds) > 0 {
					success = true
					total := len(result.Creds) + len(kr.Creds)
					if total > 0 {
						utils.StepOk(fmt.Sprintf("%d credential(s) acquired", total))
					}
					for _, c := range append(kr.Creds, result.Creds...) {
						secret := ""
						if c.Secret != "" {
							secret = utils.ValStyle.Render(c.Secret)
						}
						utils.Finding(fmt.Sprintf("%s\\%s", c.Domain, c.Username), secret)
					}
				} else {
					utils.StepFail("Credential acquisition failed")
				}

			case core.PhaseValidation:
				result := modules.RunValidation(state, targetHost)
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				if err := DB.SaveState(state); err != nil {
					return fmt.Errorf("save state: %w", err)
				}
				success = result.Success

			case core.PhaseSessionHarvest:
				provider, pErr := modules.ProviderFromState(state, targetHost, sink)
				if pErr != nil {
					fmt.Printf("[!] %v\n", pErr)
					break
				}
				result := modules.RunSessionHarvest(context.Background(), provider, state)
				if result.Success {
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					DB.SaveSessions(result.Sessions)
					state.Sessions = result.Sessions
					success = true
					utils.StepOk(fmt.Sprintf("%d session(s) harvested", len(result.Sessions)))
				}

			case core.PhaseGraphAnalysis:
				provider, pErr := modules.ProviderFromState(state, targetHost, sink)
				if pErr != nil {
					fmt.Printf("[!] %v\n", pErr)
					break
				}
				result := modules.RunGraphAnalysis(context.Background(), provider)
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
					success = true
					utils.StepOk(fmt.Sprintf("%d computer(s), %d GPO(s), %d ADCS template(s)",
						len(result.Computers), len(result.GPOs), len(result.ADCS)))
				}

			case core.PhaseLateral:
				result := modules.RunLateral(state, targetHost)
				if result.Success {
					for _, h := range result.Hosts {
						DB.SaveHost(h)
					}
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					success = true
				}

			case core.PhasePrivEsc:
				result := modules.RunPrivesc(state, targetHost, evasionProfile, executePaths)
				if result.Success {
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					if err := DB.SaveState(state); err != nil {
						fmt.Printf("[!] save state after privesc: %v\n", err)
					}
					success = true
					utils.StepOk("Privesc checks completed")
				}

			case core.PhasePersistence:
				result := modules.RunPersistence(state, targetHost)
				if result.Success {
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					if err := DB.SaveState(state); err != nil {
						fmt.Printf("[!] save state after persistence: %v\n", err)
					}
					success = true
					utils.StepOk("Persistence mechanisms deployed")
				}

			case core.PhaseImpact:
				utils.Step("Executing mission objective...")
				result := modules.RunImpact(state)
				if result.Success {
					success = true
					utils.StepOk("Impact phase complete")
				}

			case core.PhaseHybridBridge:
				utils.Step("Probing hybrid identity bridge...")
				result := modules.RunHybridBridge(state)
				if result.Success {
					success = true
					utils.StepOk("Hybrid bridge analysis complete")
				}

			default:
				return fmt.Errorf("phase %q has no implementation", rec.Phase)
			}

			elapsed := time.Since(start).Round(time.Millisecond)

			if success {
				state.Phases[rec.Phase] = core.PhaseComplete
				DB.SavePhases(state)
				utils.PhaseComplete(elapsed)
			} else {
				status := core.PhaseFailed
				if !skipFail {
					status = core.PhaseUntouched
				}
				state.Phases[rec.Phase] = status
				if status == core.PhaseFailed {
					switch rec.Phase {
					case core.PhaseCredentialAcq:
						state.SkipReasons[rec.Phase] = core.SkipNoCreds
					case core.PhaseSessionHarvest:
						state.SkipReasons[rec.Phase] = core.SkipNoSession
					case core.PhasePrivEsc:
						state.SkipReasons[rec.Phase] = core.SkipNoSystemContext
					default:
						state.SkipReasons[rec.Phase] = core.SkipNoPath
					}
				}
				DB.SavePhases(state)
				utils.PhaseFailed(elapsed)
				if !skipFail {
					utils.StepWarn("Stopping on phase failure (--skip-fail=false).")
					break
				}
			}

			freshState, loadErr := DB.LoadState()
			if loadErr != nil {
				utils.StepWarn(fmt.Sprintf("DB.LoadState error during credential re-run check: %v", loadErr))
			}
			if loadErr == nil && len(freshState.Creds) > credsAtLastRun && credAcqReruns < 2 {
				credsAtLastRun = len(freshState.Creds)
				credAcqReruns++
				for _, p := range []core.Phase{core.PhaseCredentialAcq, core.PhaseValidation} {
					if freshState.Phases[p] != core.PhaseInProgress {
						freshState.Phases[p] = core.PhaseUntouched
					}
				}
				utils.StepInfo(fmt.Sprintf("New creds appeared (%d total) — re-running credential acquisition (re-run %d/3)", credsAtLastRun, credAcqReruns))
				DB.SavePhases(freshState)
				state.Phases = freshState.Phases
			}

			fmt.Println()
			phasesRun++
			time.Sleep(500 * time.Millisecond)
		}

		// ── Save final state ──────────────────────────────────────────────
		if err := DB.SaveState(state); err != nil {
			fmt.Printf("[!] final save state: %v\n", err)
		}

		// ── Summary ───────────────────────────────────────────────────────
		state, _ = DB.LoadState()
		utils.Summary(phasesRun, len(state.Hosts), len(state.Users), len(state.Creds), countValidated(state.Creds))
		fmt.Println()

		modules.PrintLootSummary(state)
		modules.PrintVulnCoverage(modules.AssessVulnCoverage(state))
		fmt.Println()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(autoRunCmd)
	autoRunCmd.Flags().StringVarP(&evasionProfile, "evasion-profile", "e", "",
		"Evasion profile (native|pplshade|phantomkiller)")
	autoRunCmd.Flags().StringVarP(&targetHost, "target", "t", "",
		"Target host IP or hostname")
	autoRunCmd.Flags().IntVarP(&maxPhases, "max", "m", 0,
		"Maximum number of phases to run (0 = unlimited)")
	autoRunCmd.Flags().BoolVar(&skipFail, "skip-fail", true,
		"Continue to next phase when a phase fails instead of stopping (default: true)")
	autoRunCmd.Flags().StringVar(&seedDomain, "domain", "", "Target domain (seeds initial credential)")
	autoRunCmd.Flags().StringVar(&seedUser, "user", "", "Username (seeds initial credential)")
	autoRunCmd.Flags().StringVar(&seedPass, "password", "", "Password (seeds initial credential)")
	autoRunCmd.Flags().StringVar(&providerLogPath, "provider-log", "", "Write provider acquisition events as JSONL to this path")
	autoRunCmd.Flags().BoolVarP(&executePaths, "execute", "x", false, "Execute planned privilege escalation paths")
}
