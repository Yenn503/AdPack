package cmd

import (
	"adpack/modules"
	"github.com/spf13/cobra"
)

var dpapiDCIP, dpapiUser, dpapiPass, dpapiDomain, dpapiFile, dpapiPVK, dpapiKey string

var dpapiCmd = &cobra.Command{Use: "dpapi", Short: "DPAPI credential decryption"}

var dpapiBackupKeyCmd = &cobra.Command{
	Use: "backupkey", Short: "Extract domain backup key",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).BackupKey(dpapiDCIP, dpapiUser, dpapiPass, dpapiDomain)
	},
}
var dpapiMasterKeyCmd = &cobra.Command{
	Use: "masterkey", Short: "Decrypt masterkey",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).MasterKey(dpapiFile, dpapiPVK)
	},
}
var dpapiBlobCmd = &cobra.Command{
	Use: "blob", Short: "Decrypt credential blob",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).Blob(dpapiFile, dpapiKey)
	},
}
var dpapiVaultCmd = &cobra.Command{
	Use: "vault", Short: "Decrypt vault cred",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).Vault(dpapiFile, dpapiKey)
	},
}
var dpapiChromeCmd = &cobra.Command{
	Use: "chrome", Short: "Decrypt browser creds",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).Chrome(dpapiFile, dpapiKey)
	},
}
var dpapiTriageCmd = &cobra.Command{
	Use: "triage", Short: "dploot triage all machines",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).Triage(dpapiDCIP, dpapiUser, dpapiPass, dpapiDomain)
	},
}
var dpapiCredentialsCmd = &cobra.Command{
	Use: "credentials", Short: "dploot credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.DPAPIManager{}).Credentials(dpapiDCIP, dpapiUser, dpapiPass, dpapiDomain)
	},
}

func init() {
	flags := dpapiCmd.PersistentFlags()
	flags.StringVar(&dpapiDCIP, "dc-ip", "", "Domain controller IP")
	flags.StringVar(&dpapiUser, "user", "", "Username")
	flags.StringVar(&dpapiPass, "password", "", "Password")
	flags.StringVar(&dpapiDomain, "domain", "", "Domain")
	flags.StringVar(&dpapiFile, "file", "", "File path")
	flags.StringVar(&dpapiPVK, "pvk", "", "PVK key file")
	flags.StringVar(&dpapiKey, "key", "", "Masterkey hex")
	dpapiCmd.AddCommand(dpapiBackupKeyCmd, dpapiMasterKeyCmd, dpapiBlobCmd, dpapiVaultCmd, dpapiChromeCmd, dpapiTriageCmd, dpapiCredentialsCmd)
	rootCmd.AddCommand(dpapiCmd)
}
