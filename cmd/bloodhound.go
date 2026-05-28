package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"adpack/utils"
	"github.com/spf13/cobra"
)

var (
	bhOutputDir     string
	bhCollectDomain string
	bhCollectUser   string
	bhCollectPass   string
	bhCollectDC     string
)

var bloodHoundCmd = &cobra.Command{
	Use:   "bloodhound",
	Short: "Run BloodHound collection and ingestion",
	Long:  `Collects AD data using bloodhound-python and ingests results into the DB.`,
}

var bhCollectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Run bloodhound-python collection",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := bhCollectDomain
		user := bhCollectUser
		pass := bhCollectPass
		dc := bhCollectDC

		if domain == "" || user == "" || pass == "" {
			d, u, p, _ := getCreds()
			if domain == "" {
				domain = d
			}
			if user == "" {
				user = u
			}
			if pass == "" {
				pass = p
			}
		}
		if domain == "" || user == "" {
			return fmt.Errorf("credentials required: set --domain, --user, --password")
		}
		if dc == "" {
			dc = domain
		}
		if bhOutputDir == "" {
			bhOutputDir = filepath.Join(os.TempDir(), "bloodhound")
		}
		os.MkdirAll(bhOutputDir, 0755)

		fmt.Printf("[*] Running bloodhound-python against %s (DC: %s)...\n", domain, dc)
		r := utils.RunCommand("bloodhound-python",
			"-d", domain,
			"-u", user,
			"-p", pass,
			"-dc", dc,
			"-c", "All",
			"--zip",
			"--outputdir", bhOutputDir,
		)
		if !r.Success {
			return fmt.Errorf("bloodhound-python failed: %s", r.Stderr)
		}
		fmt.Printf("[+] BloodHound data collected to %s\n", bhOutputDir)
		return nil
	},
}

func getCreds() (string, string, string, string) {
	state, err := DB.LoadState()
	if err != nil {
		return "", "", "", ""
	}
	for _, c := range state.Creds {
		if c.Validated {
			return c.Domain, c.Username, c.Secret, c.Hash
		}
	}
	if len(state.Creds) > 0 {
		c := state.Creds[0]
		return c.Domain, c.Username, c.Secret, c.Hash
	}
	return "", "", "", ""
}

func init() {
	rootCmd.AddCommand(bloodHoundCmd)
	bloodHoundCmd.AddCommand(bhCollectCmd)
	bhCollectCmd.Flags().StringVarP(&bhCollectDomain, "domain", "d", "", "Target domain")
	bhCollectCmd.Flags().StringVarP(&bhCollectUser, "user", "u", "", "Username")
	bhCollectCmd.Flags().StringVarP(&bhCollectPass, "password", "p", "", "Password")
	bhCollectCmd.Flags().StringVar(&bhCollectDC, "dc", "", "Domain controller hostname (default: same as domain)")
	bhCollectCmd.Flags().StringVar(&bhOutputDir, "output", "", "Output directory (default: temp dir)")

	queryCmd.AddCommand(&cobra.Command{
		Use:   "run-bh",
		Short: "Collect BloodHound data and update DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			return bhCollectCmd.RunE(cmd, args)
		},
	})
}
