package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"adpack/core"
)

var ingestCmd = &cobra.Command{
	Use:   "ingest [file]",
	Short: "Ingest tool output (bloodhound JSON, secretsdump, etc.)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		fmt.Printf("Ingesting %s (%d bytes)...\n", path, len(data))
		state, err := DB.LoadState()
		if err != nil {
			state = core.NewADState()
		}
		fmt.Println("Parsing output...")
		if err := DB.SavePhases(state.Phases); err != nil {
			return fmt.Errorf("save phases: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ingestCmd)
}
