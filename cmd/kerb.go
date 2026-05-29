package cmd

import (
	"fmt"

	"adpack/modules"

	"github.com/spf13/cobra"
)

var (
	kerbUser        string
	kerbPass        string
	kerbHash        string
	kerbAESKey      string
	kerbDCIP        string
	kerbImpersonate string
	kerbSPN         string
)

var kerbCmd = &cobra.Command{
	Use:   "kerb",
	Short: "Kerberos ticket management (TGT, list, destroy, S4U)",
	Long:  "Manage Kerberos tickets: request TGTs, list active tickets, destroy caches, and perform S4U2self/S4U2proxy delegation.",
}

var kerbTGTCmd = &cobra.Command{
	Use:   "tgt <user>@<domain>",
	Short: "Request a TGT and set KRB5CCNAME",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		user, domain := parseUserDomain(args[0])
		if user == "" || domain == "" {
			return fmt.Errorf("invalid format — use user@domain")
		}
		km := &modules.KerberosManager{}
		return km.GetTGT(user, domain, kerbPass, kerbHash, kerbAESKey, kerbDCIP)
	},
}

var kerbListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active Kerberos tickets",
	RunE: func(cmd *cobra.Command, args []string) error {
		km := &modules.KerberosManager{}
		return km.ListTickets()
	},
}

var kerbDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy the current Kerberos ticket cache",
	RunE: func(cmd *cobra.Command, args []string) error {
		km := &modules.KerberosManager{}
		return km.DestroyTickets()
	},
}

var kerbS4UCmd = &cobra.Command{
	Use:   "s4u",
	Short: "Perform S4U2self + S4U2proxy delegation",
	RunE: func(cmd *cobra.Command, args []string) error {
		if kerbUser == "" {
			return fmt.Errorf("--user is required (format: user@domain)")
		}
		user, domain := parseUserDomain(kerbUser)
		if user == "" || domain == "" {
			return fmt.Errorf("invalid --user format — use user@domain")
		}
		km := &modules.KerberosManager{}
		return km.S4U(user, domain, kerbPass, kerbHash, kerbImpersonate, kerbSPN, kerbDCIP)
	},
}

func parseUserDomain(s string) (user, domain string) {
	parts := splitAt(s, '@')
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func splitAt(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func init() {
	kerbCmd.PersistentFlags().StringVar(&kerbDCIP, "dc-ip", "", "Domain controller IP")
	kerbCmd.PersistentFlags().StringVar(&kerbPass, "password", "", "User password")
	kerbCmd.PersistentFlags().StringVar(&kerbHash, "hashes", "", "NTLM hash (:LM:NTLM format)")
	kerbCmd.PersistentFlags().StringVar(&kerbAESKey, "aes-key", "", "AES256 key")

	kerbTGTCmd.Flags().StringVar(&kerbDCIP, "dc-ip", "", "Domain controller IP")

	kerbS4UCmd.Flags().StringVar(&kerbUser, "user", "", "User to authenticate as (user@domain)")
	kerbS4UCmd.Flags().StringVar(&kerbImpersonate, "impersonate", "", "User to impersonate")
	kerbS4UCmd.Flags().StringVar(&kerbSPN, "spn", "", "Target service SPN")

	kerbCmd.AddCommand(kerbTGTCmd, kerbListCmd, kerbDestroyCmd, kerbS4UCmd)
	rootCmd.AddCommand(kerbCmd)
}
