package cmd

import (
	"adpack/modules"

	"github.com/spf13/cobra"
)

var (
	adcsDCIP, adcsTemplate, adcsUPN, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA, adcsPFX, adcsListen, adcsTarget string
)

var adcsCmd = &cobra.Command{
	Use: "adcs", Short: "ADCS exploitation via certipy",
}

var adcsFindCmd = &cobra.Command{
	Use: "find", Short: "Find vulnerable ADCS templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).Find(adcsDCIP, adcsUser, adcsPass, adcsHash, adcsDomain)
	},
}

var adcsESC1Cmd = &cobra.Command{
	Use: "esc1", Short: "ESC1: subject name supply + client auth",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC1(adcsDCIP, adcsTemplate, adcsUPN, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA)
	},
}

var adcsESC3Cmd = &cobra.Command{
	Use: "esc3", Short: "ESC3: enrollment agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC3(adcsDCIP, adcsTemplate, adcsUPN, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA)
	},
}

var adcsESC4Cmd = &cobra.Command{
	Use: "esc4", Short: "ESC4: write access to template ACL",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC4(adcsDCIP, adcsTemplate, adcsUser, adcsPass, adcsHash, adcsDomain)
	},
}

var adcsESC6Cmd = &cobra.Command{
	Use: "esc6", Short: "ESC6: CA flag abuse",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC6(adcsDCIP, adcsTemplate, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA)
	},
}

var adcsESC8Cmd = &cobra.Command{
	Use: "esc8", Short: "ESC8: NTLM relay to ADCS HTTP",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC8(adcsDCIP, adcsListen, adcsUser, adcsPass, adcsHash, adcsDomain, adcsTemplate)
	},
}

var adcsESC9Cmd = &cobra.Command{
	Use: "esc9", Short: "ESC9: no security extension",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC9(adcsDCIP, adcsTemplate, adcsTarget, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA)
	},
}

var adcsESC10Cmd = &cobra.Command{
	Use: "esc10", Short: "ESC10: weak cert mapping",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC10(adcsDCIP, adcsTarget, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA)
	},
}

var adcsESC13Cmd = &cobra.Command{
	Use: "esc13", Short: "ESC13: OID group link",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).ESC13(adcsDCIP, adcsTemplate, adcsUser, adcsPass, adcsHash, adcsDomain, adcsCA)
	},
}

var adcsAuthCmd = &cobra.Command{
	Use: "auth", Short: "Authenticate with PFX certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.ADCSManager{}).Auth(adcsPFX, adcsDCIP)
	},
}

func init() {
	flags := adcsCmd.PersistentFlags()
	flags.StringVar(&adcsDCIP, "dc-ip", "", "Domain controller IP")
	flags.StringVar(&adcsTemplate, "template", "", "Certificate template name")
	flags.StringVar(&adcsUPN, "upn", "", "Target UPN for impersonation")
	flags.StringVar(&adcsUser, "user", "", "Username")
	flags.StringVar(&adcsPass, "password", "", "Password")
	flags.StringVar(&adcsHash, "hashes", "", "NTLM hash")
	flags.StringVar(&adcsDomain, "domain", "", "Domain")
	flags.StringVar(&adcsCA, "ca", "", "CA name")
	flags.StringVar(&adcsPFX, "pfx", "", "PFX file path")
	flags.StringVar(&adcsListen, "listen", "", "Attacker IP for relay")
	flags.StringVar(&adcsTarget, "target", "", "Target user")

	adcsCmd.AddCommand(adcsFindCmd, adcsESC1Cmd, adcsESC3Cmd, adcsESC4Cmd, adcsESC6Cmd,
		adcsESC8Cmd, adcsESC9Cmd, adcsESC10Cmd, adcsESC13Cmd, adcsAuthCmd)
	rootCmd.AddCommand(adcsCmd)
}
