package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/utils"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/spf13/cobra"
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
				if state.SkipReasons != nil {
					if r, ok := state.SkipReasons[p]; ok && r != "" {
						statusStr += lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(" [" + string(r) + "]")
					}
				}
			case core.PhaseFailed:
				statusStr = utils.ErrorStyle.Render("✗ failed")
				if state.SkipReasons != nil {
					if r, ok := state.SkipReasons[p]; ok && r != "" {
						statusStr += lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(" [" + string(r) + "]")
					}
				}
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

// showRuntimeStatus prints active services and ephemeral edges from state.
func showRuntimeStatus(state *core.ADState) {
	if len(state.Runtime.ActiveServices) == 0 && len(state.Runtime.EphemeralEdges) == 0 {
		fmt.Println("  No runtime services recorded in state")
		return
	}

	if len(state.Runtime.ActiveServices) > 0 {
		fmt.Println(utils.TitleStyle.Render("  Runtime Services"))
		t := table.New().
			Border(lipgloss.RoundedBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(utils.ColorSecondary)).
			Headers("ID", "TYPE", "STATE", "AGE").
			StyleFunc(func(row, col int) lipgloss.Style {
				if row == 0 {
					return lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary)
				}
				return utils.BaseStyle
			})

		for id, svc := range state.Runtime.ActiveServices {
			stateStr := "stopped"
			switch svc.State {
			case core.ServiceRunning:
				stateStr = utils.SuccessStyle.Render("running")
			case core.ServiceFailed:
				stateStr = utils.ErrorStyle.Render("failed")
			case core.ServiceDegraded:
				stateStr = utils.WarningStyle.Render("degraded")
			}
			age := "unknown"
			if !svc.LastHeartbeat.IsZero() {
				d := time.Since(svc.LastHeartbeat)
				if d < 0 {
					d = 0
				}
				age = fmt.Sprintf("%.0fs ago", d.Seconds())
			}
			t.Row(id, string(svc.Type), stateStr, age)
		}
		fmt.Println(t.Render())
	}

	if len(state.Runtime.EphemeralEdges) > 0 {
		fmt.Println()
		fmt.Println(utils.TitleStyle.Render("  Ephemeral Edges"))
		for _, e := range state.Runtime.EphemeralEdges {
			fmt.Printf("    %s → %s [%s] (conf=%.1f)\n",
				e.SourcePrincipal, e.TargetPrincipal, e.AccessRight, e.Confidence)
		}
	}
}

var runtimeStatusCmd = &cobra.Command{
	Use:   "runtime",
	Short: "Show active runtime services and ephemeral edges",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		showRuntimeStatus(state)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().Bool("json", false, "Output state as JSON")
	statusCmd.AddCommand(runtimeStatusCmd)
}
