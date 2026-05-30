package cmd

import (
	"context"
	"fmt"

	"adpack/modules"
	"github.com/spf13/cobra"
)

var (
	cloudTenant   string
	cloudUser     string
	cloudPassword string
	cloudUserlist string
	cloudSearch   string
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud/Entra ID attack modules (enum, cred-acq, privesc, pillage)",
}

var cloudEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate Entra ID tenant (users, groups, apps, CAPs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		result := modules.RunCloudEnumeration(context.Background(), state, cloudTenant, cloudUser, cloudPassword)
		if !result.Success {
			return fmt.Errorf("cloud enumeration failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] Cloud enumeration complete")
		return nil
	},
}

var cloudCredAcqCmd = &cobra.Command{
	Use:   "cred-acq",
	Short: "Cloud credential acquisition (O365 spray)",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		result := modules.RunCloudCredentialAcquisition(context.Background(), state, cloudTenant, cloudUserlist, cloudPassword)
		if !result.Success {
			return fmt.Errorf("cloud credential acquisition failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] Cloud credential acquisition complete")
		return nil
	},
}

var cloudPrivescCmd = &cobra.Command{
	Use:   "privesc",
	Short: "Cloud privilege escalation analysis",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		result := modules.RunCloudPrivesc(context.Background(), state, cloudTenant)
		if !result.Success {
			return fmt.Errorf("cloud privesc analysis failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] Cloud privesc analysis complete")
		return nil
	},
}

var cloudPillageCmd = &cobra.Command{
	Use:   "pillage",
	Short: "Search/export Entra ID data (mail, SharePoint, Teams)",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		terms := []string{"password", "secret", "credential", "token"}
		if cloudSearch != "" {
			terms = []string{cloudSearch}
		}
		result := modules.RunCloudPillage(context.Background(), state, terms)
		if !result.Success {
			return fmt.Errorf("cloud pillage failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] Cloud pillage complete")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(cloudCmd)
	cloudCmd.AddCommand(cloudEnumCmd)
	cloudCmd.AddCommand(cloudCredAcqCmd)
	cloudCmd.AddCommand(cloudPrivescCmd)
	cloudCmd.AddCommand(cloudPillageCmd)

	cloudEnumCmd.Flags().StringVarP(&cloudTenant, "tenant", "t", "", "Entra ID tenant")
	cloudEnumCmd.Flags().StringVarP(&cloudUser, "user", "u", "", "Username")
	cloudEnumCmd.Flags().StringVarP(&cloudPassword, "password", "p", "", "Password")

	cloudCredAcqCmd.Flags().StringVarP(&cloudTenant, "tenant", "t", "", "Entra ID tenant")
	cloudCredAcqCmd.Flags().StringVarP(&cloudUserlist, "userlist", "U", "", "User list file")
	cloudCredAcqCmd.Flags().StringVarP(&cloudPassword, "password", "p", "", "Single password to spray")

	cloudPrivescCmd.Flags().StringVarP(&cloudTenant, "tenant", "t", "", "Entra ID tenant")

	cloudPillageCmd.Flags().StringVarP(&cloudSearch, "search", "s", "", "Search term (default: password, secret, credential, token)")
}
