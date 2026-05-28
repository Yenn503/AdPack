package cmd

import (
	"adpack/modules"
	"github.com/spf13/cobra"
)

var shadowTarget, shadowUser, shadowPass, shadowDomain, shadowNTDS, shadowSystem string

var shadowCmd = &cobra.Command{Use: "shadow", Short: "Shadow copy NTDS extraction"}

var shadowNTDSCmd = &cobra.Command{
	Use: "ntds", Short: "diskshadow extract NTDS.dit",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ShadowManager{}).NTDS(shadowTarget, shadowUser, shadowPass, shadowDomain)
	},
}
var shadowIFMCmd = &cobra.Command{
	Use: "ifm", Short: "ntdsutil IFM",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ShadowManager{}).IFM(shadowTarget, shadowUser, shadowPass, shadowDomain)
	},
}
var shadowParseCmd = &cobra.Command{
	Use: "parse", Short: "Parse NTDS.dit locally",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ShadowManager{}).Parse(shadowNTDS, shadowSystem)
	},
}

func init() {
	flags := shadowCmd.PersistentFlags()
	flags.StringVar(&shadowTarget, "target", "", "Target DC IP")
	flags.StringVar(&shadowUser, "user", "", "Username")
	flags.StringVar(&shadowPass, "password", "", "Password")
	flags.StringVar(&shadowDomain, "domain", "", "Domain")
	shadowParseCmd.Flags().StringVar(&shadowNTDS, "ntds", "", "NTDS.dit file path")
	shadowParseCmd.Flags().StringVar(&shadowSystem, "system", "", "SYSTEM hive file path")
	shadowCmd.AddCommand(shadowNTDSCmd, shadowIFMCmd, shadowParseCmd)
	rootCmd.AddCommand(shadowCmd)
}
