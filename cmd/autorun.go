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

Use --max to limit the number of phases executed. Use --skip-fail to continue
past failed phases instead of stopping.`,
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

		// Seed initial credentials from flags
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
		for {
			if maxPhases > 0 && phasesRun >= maxPhases {
				fmt.Printf("\n  %s  Limit reached (%d phases executed)\n",
					utils.InfoStyle.Render("■"), maxPhases)
				break
			}

			// Reload state so engine sees latest DB
			state, err = DB.LoadState()
			if err != nil {
				return fmt.Errorf("reload state: %w", err)
			}
			engine := core.NewEngine(state)

			rec := engine.Evaluate()
			if rec.Phase == "" {
				fmt.Printf("\n  %s  %s\n", utils.SuccessStyle.Render("✓"), rec.Rationale)
				break
			}

			// Phase header
			fmt.Printf("  %s  %s\n",
				lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary).Render(fmt.Sprintf("[%d]", phasesRun+1)),
				lipgloss.NewStyle().Bold(true).Render(strings.ToUpper(string(rec.Phase))))
			fmt.Printf("      %s\n\n", lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(rec.Rationale))

			state.Phases[rec.Phase] = core.PhaseInProgress
			DB.SavePhases(state.Phases)

			success := false
			start := time.Now()

			switch rec.Phase {
			case core.PhaseDiscovery:
				result := modules.RunDiscovery(state, targetHost)
				if result.Success {
					for _, h := range result.Hosts {
						DB.SaveHost(h)
					}
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					success = true
					fmt.Printf("      %s  %d host(s) discovered\n", utils.SuccessStyle.Render("✓"), len(result.Hosts))
					for _, h := range result.Hosts {
						dc := ""
						if h.IsDC {
							dc = utils.WarningStyle.Render(" [DC]")
						}
						fmt.Printf("         %s  %s%s\n",
							lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
							h.IP, dc)
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
					fmt.Printf("      %s  %d user(s) enumerated\n", utils.SuccessStyle.Render("✓"), len(result.Users))
					if len(result.Creds) > 0 {
						fmt.Printf("      %s  %d credential(s) found in descriptions\n",
							utils.SuccessStyle.Render("✓"), len(result.Creds))
					}
				}

			case core.PhaseCredentialAcq:
				fmt.Printf("      %s  Kerberos pre-check...\n", utils.InfoStyle.Render("→"))
				kr := modules.RunKerberos(state, targetHost)
				for _, u := range kr.Users {
					DB.SaveUser(u)
				}
				for _, c := range kr.Creds {
					DB.SaveCred(c)
				}
				for _, ev := range kr.Evidence {
					DB.SaveEvidence(ev)
				}

				result := modules.RunCredentialAcq(state, evasionProfile, targetHost)
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				if result.Success {
					for _, c := range result.Creds {
						DB.SaveCred(c)
					}
					success = true
					fmt.Printf("      %s  %d credential(s) acquired\n", utils.SuccessStyle.Render("✓"), len(result.Creds))
					for _, c := range result.Creds {
						secret := ""
						if c.Secret != "" {
							secret = "  " + lipgloss.NewStyle().Foreground(utils.ColorWarning).Render(c.Secret)
						}
						fmt.Printf("         %s  %s\\%s%s\n",
							lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
							c.Domain, c.Username, secret)
					}
				} else {
					fmt.Printf("      %s  Credential acquisition failed\n", utils.ErrorStyle.Render("✗"))
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
					fmt.Printf("      %s  %d session(s) harvested\n", utils.SuccessStyle.Render("✓"), len(result.Sessions))
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
					fmt.Printf("      %s  %d computer(s), %d GPO(s), %d ADCS template(s)\n",
						utils.SuccessStyle.Render("✓"),
						len(result.Computers), len(result.GPOs), len(result.ADCS))
				}

			case core.PhaseLateral:
				result := modules.RunLateral(state, targetHost)
				if result.Success {
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
					success = true
					fmt.Printf("      %s  Privesc checks completed\n", utils.SuccessStyle.Render("✓"))
				}

			case core.PhasePersistence:
				result := modules.RunPersistence(state, targetHost)
				if result.Success {
					for _, ev := range result.Evidence {
						DB.SaveEvidence(ev)
					}
					success = true
					fmt.Printf("      %s  Persistence mechanisms deployed\n", utils.SuccessStyle.Render("✓"))
				}

			default:
				return fmt.Errorf("phase %q has no implementation", rec.Phase)
			}

			elapsed := time.Since(start).Round(time.Millisecond)

			if success {
				state.Phases[rec.Phase] = core.PhaseComplete
				DB.SavePhases(state.Phases)
				fmt.Printf("\n      %s  %s  %s\n",
					utils.SuccessStyle.Render("✓ complete"),
					lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("·"),
					lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(elapsed.String()))
			} else {
				status := core.PhaseSkipped
				if !skipFail {
					status = core.PhaseUntouched
				}
				state.Phases[rec.Phase] = status
				DB.SavePhases(state.Phases)
				fmt.Printf("\n      %s  %s\n",
					utils.ErrorStyle.Render("✗ failed"),
					lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(elapsed.String()))
				if !skipFail {
					fmt.Printf("\n  %s  Stopping. Use --skip-fail to continue past failures.\n",
						utils.WarningStyle.Render("!"))
					break
				}
			}

			fmt.Println()
			phasesRun++
			time.Sleep(500 * time.Millisecond)
		}

		// ── Summary ───────────────────────────────────────────────────────
		state, _ = DB.LoadState()
		fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + strings.Repeat("─", 52)))
		fmt.Printf("  %s  %d phases executed  ·  %d hosts  ·  %d users  ·  %d creds (%d validated)\n",
			utils.InfoStyle.Render("■"),
			phasesRun,
			len(state.Hosts),
			len(state.Users),
			len(state.Creds),
			countValidated(state.Creds))
		fmt.Println()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(autoRunCmd)
	autoRunCmd.Flags().StringVarP(&evasionProfile, "evasion-profile", "e", "standard",
		"Evasion profile for credential acquisition")
	autoRunCmd.Flags().StringVarP(&targetHost, "target", "t", "",
		"Target host IP or hostname")
	autoRunCmd.Flags().IntVarP(&maxPhases, "max", "m", 0,
		"Maximum number of phases to run (0 = unlimited)")
	autoRunCmd.Flags().BoolVar(&skipFail, "skip-fail", false,
		"Continue to next phase when a phase fails instead of stopping")
	autoRunCmd.Flags().StringVar(&seedDomain, "domain", "", "Target domain (seeds initial credential)")
	autoRunCmd.Flags().StringVar(&seedUser, "user", "", "Username (seeds initial credential)")
	autoRunCmd.Flags().StringVar(&seedPass, "password", "", "Password (seeds initial credential)")
	autoRunCmd.Flags().StringVar(&providerLogPath, "provider-log", "", "Write provider acquisition events as JSONL to this path")
	autoRunCmd.Flags().BoolVarP(&executePaths, "execute", "x", false, "Execute planned privilege escalation paths")
}
