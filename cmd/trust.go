package cmd

import (
	"adpack/modules"

	"github.com/spf13/cobra"
)

var trustDCIP, trustUser, trustPass, trustDomain, trustTarget, trustKey string

var trustCmd = &cobra.Command{Use: "trust", Short: "Domain trust attacks"}

var trustListCmd = &cobra.Command{
	Use: "list", Short: "Enumerate domain trusts",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.TrustManager{}).List(trustDCIP, trustUser, trustPass, trustDomain)
	},
}
var trustKeysCmd = &cobra.Command{
	Use: "keys", Short: "Extract trust keys (DA required)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.TrustManager{}).Keys(trustDCIP, trustUser, trustPass, trustDomain)
	},
}
var trustInterRealmCmd = &cobra.Command{
	Use: "inter-realm", Short: "Forge inter-realm TGT",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.TrustManager{}).InterRealm(trustTarget, trustDCIP, trustUser, trustPass, trustDomain, trustKey)
	},
}
var trustSIDHistoryCmd = &cobra.Command{
	Use: "sidhistory", Short: "SIDHistory injection",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.TrustManager{}).SIDHistory(trustTarget, trustDCIP, trustUser, trustPass, trustDomain, trustKey)
	},
}

func init() {
	flags := trustCmd.PersistentFlags()
	flags.StringVar(&trustDCIP, "dc-ip", "", "Domain controller IP")
	flags.StringVar(&trustUser, "user", "", "Username")
	flags.StringVar(&trustPass, "password", "", "Password")
	flags.StringVar(&trustDomain, "domain", "", "Domain")
	flags.StringVar(&trustTarget, "target", "", "Target domain")
	flags.StringVar(&trustKey, "key", "", "Trust key (NT hash)")
	trustCmd.AddCommand(trustListCmd, trustKeysCmd, trustInterRealmCmd, trustSIDHistoryCmd)
	rootCmd.AddCommand(trustCmd)
}
