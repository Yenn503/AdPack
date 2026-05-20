package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"adpack/core"
)

type bhComputer struct {
	Name            string `json:"name"`
	Domain          string `json:"domain"`
	OperatingSystem string `json:"operatingsystem"`
	Enabled         bool   `json:"enabled"`
	SID             string `json:"objectsid"`
}

type bhUser struct {
	Name    string   `json:"name"`
	Domain  string   `json:"domain"`
	Enabled bool     `json:"enabled"`
	SID     string   `json:"objectsid"`
	IsDA    bool     `json:"isdomainadmin"`
	IsAdmin bool     `json:"isadmin"`
	SPNs    []string `json:"serviceprincipalnames"`
}

type bhGroup struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	SID    string `json:"objectsid"`
}

type bhData struct {
	Computers []bhComputer `json:"computers"`
	Users     []bhUser     `json:"users"`
	Groups    []bhGroup    `json:"groups"`
	Meta      map[string]any `json:"meta"`
}

type bhFile struct {
	Data []bhData `json:"data"`
}

var ingestCmd = &cobra.Command{
	Use:   "ingest [file or directory]",
	Short: "Ingest BloodHound JSON files into DB",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat: %w", err)
		}

		var files []string
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("read dir: %w", err)
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".json") {
					files = append(files, filepath.Join(path, e.Name()))
				}
			}
		} else {
			files = append(files, path)
		}

		for _, f := range files {
			fmt.Printf("[*] Ingesting %s...\n", f)
			data, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("read %s: %w", f, err)
			}

			var bf bhFile
			if err := json.Unmarshal(data, &bf); err != nil {
				return fmt.Errorf("parse %s: %w", f, err)
			}

			for _, d := range bf.Data {
				for _, c := range d.Computers {
					computer := core.Computer{
						Name: c.Name, Domain: c.Domain,
						OperatingSystem: c.OperatingSystem,
						SID:             c.SID,
					}
					if err := DB.SaveComputer(computer); err != nil {
						return fmt.Errorf("save computer: %w", err)
					}
				}
				for _, u := range d.Users {
					user := core.User{
						Username: u.Name, Domain: u.Domain,
						Enabled: u.Enabled, SID: u.SID,
						IsDA: u.IsDA, IsAdmin: u.IsAdmin,
						SPNs: strings.Join(u.SPNs, ","), Source: "bloodhound",
					}
					if err := DB.SaveUser(user); err != nil {
						return fmt.Errorf("save user: %w", err)
					}
				}
				for _, g := range d.Groups {
					group := core.Group{
						Name: g.Name, Domain: g.Domain, SID: g.SID,
					}
					if err := DB.SaveGroup(group); err != nil {
						return fmt.Errorf("save group: %w", err)
					}
				}
			}
		}

		fmt.Printf("[+] Ingested %d file(s)\n", len(files))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ingestCmd)
}
