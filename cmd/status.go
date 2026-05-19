package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/spf13/cobra"
	"adpack/core"
	"adpack/utils"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current state summary and gaps",
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOut, _ := cmd.Flags().GetBool("json")

		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}

		if jsonOut {
			b, _ := json.MarshalIndent(state, "", "  ")
			fmt.Println(string(b))
			return nil
		}

		// ── Header stats box ──────────────────────────────────────────────
		validated := countValidated(state.Creds)
		statsLines := []string{
			fmt.Sprintf("  Hosts        %s", utils.InfoStyle.Render(fmt.Sprintf("%d discovered (%d DC)", len(state.Hosts), countDCs(state.Hosts)))),
			fmt.Sprintf("  Users        %s", utils.InfoStyle.Render(fmt.Sprintf("%d enumerated", len(state.Users)))),
			fmt.Sprintf("  Credentials  %s", utils.InfoStyle.Render(fmt.Sprintf("%d acquired (%d validated)", len(state.Creds), validated))),
			fmt.Sprintf("  Sessions     %s", utils.InfoStyle.Render(fmt.Sprintf("%d active", len(state.Sessions)))),
			fmt.Sprintf("  BloodHound   %s", utils.InfoStyle.Render(bhStatus(state.BH))),
		}
		statsBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(utils.ColorSecondary).
			Padding(0, 1).
			Width(60).
			Render(strings.Join(statsLines, "\n"))

		fmt.Println(utils.TitleStyle.Render("  State"))
		fmt.Println(statsBox)

		// ── Phase table ───────────────────────────────────────────────────
		fmt.Println()
		t := table.New().
			Border(lipgloss.RoundedBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(utils.ColorSecondary)).
			Headers("PHASE", "STATUS").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary)
				}
				return utils.BaseStyle
			})

		for _, p := range core.AllPhases {
			st := state.Phases[p]
			var statusStr string
			switch st {
			case core.PhaseInProgress:
				statusStr = utils.WarningStyle.Render("● in-progress")
			case core.PhaseComplete:
				statusStr = utils.SuccessStyle.Render("✓ complete")
			case core.PhaseSkipped:
				statusStr = utils.InfoStyle.Render("⊘ skipped")
			default:
				statusStr = lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("○ pending")
			}
			t.Row(string(p), statusStr)
		}
		fmt.Println(t.Render())

		// ── Gaps ──────────────────────────────────────────────────────────
		gaps := state.DetectGaps()
		if len(gaps) > 0 {
			fmt.Println()
			fmt.Println(utils.TitleStyle.Render("  Gaps"))
			for _, g := range gaps {
				var icon string
				var style lipgloss.Style
				if g.Severity == "high" {
					icon = "✗"
					style = utils.ErrorStyle
				} else {
					icon = "!"
					style = utils.WarningStyle
				}
				fmt.Printf("  %s  %s\n", style.Render(icon), g.Message)
			}
		}

		// ── Recommendation ────────────────────────────────────────────────
		next := state.NextPhase()
		if next != nil {
			engine := core.NewEngine(state)
			rec := engine.Evaluate()
			fmt.Println()
			fmt.Printf("  %s  %s\n", utils.InfoStyle.Render("→ Next:"), utils.SuccessStyle.Render(string(*next)))
			fmt.Printf("  %s  %s\n", utils.InfoStyle.Render("  Why: "), rec.Rationale)
		}

		return nil
	},
}

func countValidated(cc []core.Credential) int {
	n := 0
	for _, c := range cc {
		if c.Validated {
			n++
		}
	}
	return n
}

func countDCs(hh []core.Host) int {
	n := 0
	for _, h := range hh {
		if h.IsDC {
			n++
		}
	}
	return n
}

func bhStatus(bh core.BloodhoundMeta) string {
	if bh.Ingested {
		return fmt.Sprintf("ingested (%d DA users)", bh.DACount)
	}
	if bh.Collected {
		return "collected, not ingested"
	}
	return "not collected"
}

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().Bool("json", false, "Output state as JSON")
}
