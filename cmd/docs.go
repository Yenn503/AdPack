package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"adpack/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var docsOutputDir string

var docsCmd = &cobra.Command{
	Use:    "docs",
	Short:  "Generate CLI documentation from command definitions",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := docsOutputDir
		if dir == "" {
			dir = "docs/cli"
		}

		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create docs dir: %w", err)
		}

		utils.Step(fmt.Sprintf("Generating CLI docs in %s...", dir))

		if err := doc.GenMarkdownTree(rootCmd, dir); err != nil {
			return fmt.Errorf("generate markdown: %w", err)
		}

		// Generate a single combined markdown file for easy reference
		combined, err := os.Create(filepath.Join(dir, "README.md"))
		if err != nil {
			return fmt.Errorf("create combined doc: %w", err)
		}
		defer combined.Close()

		if _, err := fmt.Fprint(combined, "# AdPack CLI Reference\n\n"); err != nil {
			return fmt.Errorf("write header: %w", err)
		}
		if _, err := fmt.Fprint(combined, "Auto-generated from command definitions. Do not edit manually.\n\n"); err != nil {
			return fmt.Errorf("write subheader: %w", err)
		}

		for _, c := range rootCmd.Commands() {
			if c.Hidden {
				continue
			}
			if _, err := fmt.Fprintf(combined, "## `adpack %s`\n\n", c.Name()); err != nil {
				return fmt.Errorf("write command %s: %w", c.Name(), err)
			}
			if _, err := fmt.Fprintf(combined, "%s\n\n", c.Short); err != nil {
				return fmt.Errorf("write short %s: %w", c.Name(), err)
			}
			if c.Long != "" {
				if _, err := fmt.Fprintf(combined, "%s\n\n", c.Long); err != nil {
					return fmt.Errorf("write long %s: %w", c.Name(), err)
				}
			}
			if len(c.Commands()) > 0 {
				if _, err := fmt.Fprint(combined, "### Subcommands\n\n"); err != nil {
					return fmt.Errorf("write subcommands header %s: %w", c.Name(), err)
				}
				for _, sub := range c.Commands() {
					if sub.Hidden {
						continue
					}
					if _, err := fmt.Fprintf(combined, "- **`%s`** — %s\n", sub.Name(), sub.Short); err != nil {
						return fmt.Errorf("write subcommand %s: %w", sub.Name(), err)
					}
				}
				if _, err := fmt.Fprintln(combined); err != nil {
					return fmt.Errorf("write newline: %w", err)
				}
			}
		}

		utils.StepOk(fmt.Sprintf("CLI docs generated: %s", dir))
		return nil
	},
}

func init() {
	docsCmd.Flags().StringVarP(&docsOutputDir, "output", "o", "docs/cli", "Output directory")
	rootCmd.AddCommand(docsCmd)
}
