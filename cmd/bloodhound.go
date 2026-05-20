package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"adpack/utils"
)

var bhOutputDir string

var bloodHoundCmd = &cobra.Command{
	Use:   "bloodhound",
	Short: "Run BloodHound collection and ingestion",
	Long:  `Collects AD data using bloodhound-python and ingests results into the DB.`,
}

var bhCollectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Run bloodhound-python collection",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, user, pass, _ := getCreds()
		if domain == "" || user == "" {
			return fmt.Errorf("credentials required: set --domain, --user, --password")
		}
		if bhOutputDir == "" {
			bhOutputDir = filepath.Join(os.TempDir(), "bloodhound")
		}
		os.MkdirAll(bhOutputDir, 0755)

		fmt.Printf("[*] Running bloodhound-python against %s...\n", domain)
		r := utils.RunCommand("bloodhound-python",
			"-d", domain,
			"-u", user,
			"-p", pass,
			"-dc", domain,
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
	bhCollectCmd.Flags().StringVarP(&targetHost, "domain", "d", "", "Target domain")
	bhCollectCmd.Flags().StringVarP(&evasionProfile, "user", "u", "", "Username")
	bhCollectCmd.Flags().StringVar(&bhOutputDir, "output", "", "Output directory")
	bhCollectCmd.Flags().StringVar(&targetHost, "dc", "", "DC host")

	// Also register as subcommand of query
	queryCmd.AddCommand(&cobra.Command{
		Use:   "run-bh",
		Short: "Collect BloodHound data and update DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			return bhCollectCmd.RunE(cmd, args)
		},
	})
}
