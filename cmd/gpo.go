package cmd

import (
	"adpack/modules"

	"github.com/spf13/cobra"
)

var gpoName, gpoOU, gpoTarget, gpoUser, gpoPass, gpoDomain, gpoRunCmd, gpoPayload, gpoTargetUser string

var gpoCmd = &cobra.Command{Use: "gpo", Short: "GPO abuse and enumeration"}

var gpoCreateCmd = &cobra.Command{
	Use: "create", Short: "Create and link GPO",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.GPOManager{}).Create(gpoName, gpoOU, gpoTarget, gpoUser, gpoPass, gpoDomain)
	},
}
var gpoRunKeyCmd = &cobra.Command{
	Use: "runkey", Short: "Registry RunKey via GPO",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.GPOManager{}).RunKey(gpoName, gpoRunCmd, gpoTarget, gpoUser, gpoPass, gpoDomain)
	},
}
var gpoTaskCmd = &cobra.Command{
	Use: "task", Short: "Scheduled task via GPO",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.GPOManager{}).Task(gpoName, gpoPayload, gpoTarget, gpoUser, gpoPass, gpoDomain)
	},
}
var gpoLocalAdminCmd = &cobra.Command{
	Use: "localadmin", Short: "Restricted Groups local admin",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.GPOManager{}).LocalAdmin(gpoName, gpoTargetUser, gpoTarget, gpoUser, gpoPass, gpoDomain)
	},
}
var gpoFindCmd = &cobra.Command{
	Use: "find", Short: "Enumerate GPOs + GPP passwords",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.GPOManager{}).Find(gpoTarget, gpoUser, gpoPass, gpoDomain)
	},
}

func init() {
	flags := gpoCmd.PersistentFlags()
	flags.StringVar(&gpoName, "name", "", "GPO name")
	flags.StringVar(&gpoOU, "ou", "", "OU DN to link")
	flags.StringVar(&gpoTarget, "target", "", "Target DC IP")
	flags.StringVar(&gpoUser, "user", "", "Username")
	flags.StringVar(&gpoPass, "password", "", "Password")
	flags.StringVar(&gpoDomain, "domain", "", "Domain")
	flags.StringVar(&gpoRunCmd, "cmd", "", "Command to execute")
	flags.StringVar(&gpoPayload, "payload", "", "PowerShell payload path")
	flags.StringVar(&gpoTargetUser, "target-user", "", "User to add to local admins")
	gpoCmd.AddCommand(gpoCreateCmd, gpoRunKeyCmd, gpoTaskCmd, gpoLocalAdminCmd, gpoFindCmd)
	rootCmd.AddCommand(gpoCmd)
}
