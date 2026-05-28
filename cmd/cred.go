package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var credFormat, credOutput string
var showSecrets bool

var credCmd = &cobra.Command{Use: "cred", Short: "Credential inventory management"}

var credListCmd = &cobra.Command{
	Use: "list", Short: "List all credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		switch credFormat {
		case "json":
			type credOut struct {
				Username  string `json:"username"`
				Domain    string `json:"domain"`
				Type      string `json:"type"`
				Source    string `json:"source"`
				Validated bool   `json:"validated"`
				Target    string `json:"target"`
				Secret    string `json:"secret,omitempty"`
			}
			var out []credOut
			for _, c := range state.Creds {
				co := credOut{Username: c.Username, Domain: c.Domain, Type: string(c.Type), Source: c.Source, Validated: c.Validated, Target: c.Target}
				if showSecrets {
					co.Secret = c.Secret
				} else {
					co.Secret = "***"
				}
				out = append(out, co)
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
		case "csv":
			w := csv.NewWriter(os.Stdout)
			w.Write([]string{"Username", "Domain", "Type", "Source", "Validated", "Target", "Secret"})
			for _, c := range state.Creds {
				sec := "***"
				if showSecrets {
					sec = c.Secret
				}
				w.Write([]string{c.Username, c.Domain, string(c.Type), c.Source, fmt.Sprintf("%v", c.Validated), c.Target, sec})
			}
			w.Flush()
		default:
			for _, c := range state.Creds {
				sec := "***"
				if showSecrets {
					sec = c.Secret
				}
				fmt.Printf("%s\\%s  %s  %s  validated=%v\n", c.Domain, c.Username, c.Type, sec, c.Validated)
			}
		}
		return nil
	},
}

var credExportCmd = &cobra.Command{
	Use: "export", Short: "Export credential inventory",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		type credOut struct {
			Username  string `json:"username"`
			Domain    string `json:"domain"`
			Type      string `json:"type"`
			Source    string `json:"source"`
			Validated bool   `json:"validated"`
			Target    string `json:"target"`
			Secret    string `json:"secret,omitempty"`
		}
		var out []credOut
		for _, c := range state.Creds {
			co := credOut{Username: c.Username, Domain: c.Domain, Type: string(c.Type), Source: c.Source, Validated: c.Validated, Target: c.Target}
			if showSecrets {
				co.Secret = c.Secret
			} else {
				co.Secret = "***"
			}
			out = append(out, co)
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal creds: %w", err)
		}
		return os.WriteFile(credOutput, b, 0644)
	},
}

var credStatusCmd = &cobra.Command{
	Use: "status", Short: "Show credential inventory summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		total := len(state.Creds)
		validated := 0
		plaintext := 0
		ntlm := 0
		for _, c := range state.Creds {
			if c.Validated {
				validated++
			}
			switch c.Type {
			case "plaintext":
				plaintext++
			case "ntlm":
				ntlm++
			}
		}
		fmt.Printf("Total credentials:    %d\n", total)
		fmt.Printf("Validated:            %d\n", validated)
		fmt.Printf("Plaintext:            %d\n", plaintext)
		fmt.Printf("NTLM hashes:          %d\n", ntlm)
		fmt.Printf("Unvalidated:          %d\n", total-validated)
		if total > 0 {
			fmt.Printf("Validation rate:      %.0f%%\n", float64(validated)/float64(total)*100)
		}
		return nil
	},
}

var credVerifyTarget string

var credVerifyCmd = &cobra.Command{
	Use:   "verify [username]",
	Short: "Verify a specific credential or all unvalidated creds",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		filterUser := ""
		if len(args) > 0 {
			filterUser = args[0]
		}
		count := 0
		ok := 0
		for _, c := range state.Creds {
			if c.Validated {
				continue
			}
			if filterUser != "" && c.Username != filterUser {
				continue
			}
			target := c.Target
			if credVerifyTarget != "" {
				target = credVerifyTarget
			}
			if target == "" {
				continue
			}
			count++
			fmt.Printf("Verifying %s\\%s against %s... ", c.Domain, c.Username, target)
			// Use nxc SMB to verify
			cmd := exec.Command("nxc", "smb", target, "-u", c.Username, "-p", c.Secret, "-d", c.Domain)
			out, err := cmd.CombinedOutput()
			if err == nil && (strings.Contains(string(out), "Pwn3d") || strings.Contains(string(out), "(Pwn3d!)")) {
				fmt.Println("VALID")
				c.Validated = true
				DB.SaveCred(c)
				ok++
			} else {
				fmt.Println("FAILED")
			}
		}
		fmt.Printf("\nVerified %d credentials: %d valid, %d failed\n", count, ok, count-ok)
		return nil
	},
}

func init() {
	credListCmd.Flags().StringVar(&credFormat, "format", "", "Output format (json, csv)")
	credListCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Show plaintext secrets")
	credExportCmd.Flags().StringVar(&credOutput, "output", "creds.json", "Output file")
	credExportCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Include plaintext secrets")
	credVerifyCmd.Flags().StringVarP(&credVerifyTarget, "target", "t", "", "Target host for verification")
	credCmd.AddCommand(credListCmd, credExportCmd, credStatusCmd, credVerifyCmd)
	rootCmd.AddCommand(credCmd)
}
