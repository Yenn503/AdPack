package cmd

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"adpack/tui"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Launch interactive TUI mode",
	Aliases: []string{"i", "tui", "repl"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if DB == nil {
			return fmt.Errorf("database not initialized")
		}
		p := tea.NewProgram(tui.New(DB), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}
