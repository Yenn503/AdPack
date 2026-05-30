package cmd

import (
	"fmt"
	"strings"

	"adpack/core"
	"adpack/utils"
	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"
)

var nextCmd = &cobra.Command{
	Use:   "next",
	Short: "Show recommended next action from the engine",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		engine := core.NewEngine(state)
		rec := engine.Evaluate()

		if rec.Phase == "" {
			fmt.Println(utils.SuccessStyle.Render("✓ All phases complete or no further actions available."))
			if rec.Rationale != "" {
				fmt.Printf("  %s\n", rec.Rationale)
			}
			return nil
		}

		// Phase header
		phaseBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(utils.ColorPrimary).
			Padding(0, 2).
			Bold(true).
			Foreground(utils.ColorPrimary).
			Render(fmt.Sprintf("→  %s", strings.ToUpper(string(rec.Phase))))

		fmt.Println()
		fmt.Println(phaseBox)
		fmt.Println()

		// Rationale
		fmt.Printf("  %s  %s\n", utils.InfoStyle.Render("Rationale"), rec.Rationale)
		fmt.Println()

		// Strategies
		if len(rec.Strategies) > 0 {
			fmt.Println(utils.InfoStyle.Render("  Strategies"))
			for _, s := range rec.Strategies {
				fmt.Printf("    %s  %s\n",
					lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
					s)
			}
			fmt.Println()
		}

		// Gaps
		if len(rec.Gaps) > 0 {
			fmt.Println(utils.WarningStyle.Render("  Open Gaps"))
			for _, g := range rec.Gaps {
				sev := utils.WarningStyle
				if g.Severity == "high" {
					sev = utils.ErrorStyle
				}
				fmt.Printf("    %s  %s\n", sev.Render(g.Severity), g.Message)
			}
			fmt.Println()
		}

		// Run hint
		var runHint string
		switch rec.Phase {
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
			runHint = "adpack run " + string(rec.Phase)
		}
		fmt.Printf("  %s  %s\n",
			lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("Run:"),
			runHint)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(nextCmd)
}
