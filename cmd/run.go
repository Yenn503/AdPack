package cmd

import (
	"fmt"
	"strings"

	"adpack/core"
	"adpack/modules"
	"adpack/utils"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
)

var (
	evasionProfile string
	targetHost     string
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

		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}

		// Phase header
		printPhaseHeader(phase)

		state.Phases[phase] = core.PhaseInProgress
		if err := DB.SavePhases(state.Phases); err != nil {
			return fmt.Errorf("save phases: %w", err)
		}

		var success bool

		switch phase {
		case core.PhaseDiscovery:
			result := modules.RunDiscovery(state, targetHost)
			success = result.Success
			if result.Success {
				for _, h := range result.Hosts {
					DB.SaveHost(h)
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
			}

		case core.PhaseValidation:
			result := modules.RunValidation(state, targetHost)
			success = result.Success
			for _, ev := range result.Evidence {
				DB.SaveEvidence(ev)
			}
			// Persist validated state
			if err := DB.SaveState(state); err != nil {
				return fmt.Errorf("save state: %w", err)
			}

		case core.PhaseSessionHarvest:
			result := modules.RunSessionHarvest(state, targetHost)
			success = result.Success
			if result.Success {
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
				DB.SaveSessions(result.Sessions)
				state.Sessions = result.Sessions
				printResult("Sessions harvested", len(result.Sessions))
			}

		case core.PhaseGraphAnalysis:
			result := modules.RunGraphAnalysis(state, targetHost)
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
				printResult("Computers found", len(result.Computers))
				printResult("GPOs found", len(result.GPOs))
				printResult("ADCS templates found", len(result.ADCS))
			}

		case core.PhaseLateral:
			result := modules.RunLateral(state, targetHost)
			success = result.Success
			if result.Success {
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
				}
			}

		case core.PhasePrivEsc:
			result := modules.RunPrivesc(state, targetHost)
			success = result.Success
			if result.Success {
				for _, ev := range result.Evidence {
					DB.SaveEvidence(ev)
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
				printResult("Persistence mechanisms deployed", 0)
			}

		default:
			return fmt.Errorf("phase %q has no implementation", phase)
		}

		// Update phase status
		if success {
			state.Phases[phase] = core.PhaseComplete
		} else {
			state.Phases[phase] = core.PhaseUntouched
		}
		DB.SavePhases(state.Phases)

		// Footer
		fmt.Println()
		if success {
			fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("  ✓  Phase %s complete", phase)))
		} else {
			fmt.Println(utils.ErrorStyle.Render(fmt.Sprintf("  ✗  Phase %s failed", phase)))
		}

		// Show what's next
		state, _ = DB.LoadState()
		next := state.NextPhase()
		if next != nil {
			fmt.Printf("\n  %s  adpack run %s\n",
				lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("Next:"),
				string(*next))
		}

		return nil
	},
}

func printPhaseHeader(phase core.Phase) {
	bar := strings.Repeat("─", 50)
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))
	fmt.Printf("  %s  %s\n",
		lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary).Render("PHASE"),
		lipgloss.NewStyle().Bold(true).Render(strings.ToUpper(string(phase))))
	fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))
	fmt.Println()
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
	runCmd.Flags().StringVarP(&evasionProfile, "evasion-profile", "e", "standard",
		"Evasion profile for credential acquisition")
	runCmd.Flags().StringVarP(&targetHost, "target", "t", "",
		"Target host IP or hostname")
	runCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return phaseNames(), cobra.ShellCompDirectiveNoFileComp
	}
}
