package cmd

import (
	"fmt"

	"adpack/core"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset [phase|state]",
	Short: "Reset phase status or entire state",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] == "state" {
			for _, phase := range core.AllPhases {
				if err := DB.ResetPhase(phase); err != nil {
					return fmt.Errorf("reset phase %s: %w", phase, err)
				}
			}
			fmt.Println("All phases reset.")
			return nil
		}
		phase := core.Phase(args[0])
		for _, p := range core.AllPhases {
			if p == phase {
				if err := DB.ResetPhase(p); err != nil {
					return err
				}
				fmt.Printf("Phase %s reset.\n", phase)
				return nil
			}
		}
		return fmt.Errorf("unknown phase: %s", phase)
	},
}

func init() {
	rootCmd.AddCommand(resetCmd)
}
