package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"adpack/modules"
)

var (
	validateTarget string
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate acquired credentials across multiple protocols",
	Long: `Validate credentials against target hosts using SMB, LDAP, WinRM, and RDP.
Tests each credential across multiple protocols to determine validity, admin rights,
and lateral movement potential.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		
		result := modules.RunValidation(state, validateTarget)
		
		// Save updated state
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		
		if !result.Success {
			return fmt.Errorf("validation failed or no credentials validated")
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().StringVarP(&validateTarget, "target", "t", "", "Target host IP or hostname (validates against all hosts if not specified)")
}
