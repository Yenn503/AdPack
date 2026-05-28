package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"adpack/modules"
	"adpack/utils"

	"github.com/spf13/cobra"
)

var (
	validateTarget string
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate credentials, tools, and configuration",
	Long: `Validate credentials against target hosts using SMB, LDAP, WinRM, and RDP.
Also supports tool dependency checking and config validation.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}

		result := modules.RunValidation(state, validateTarget)

		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state: %w", err)
		}

		if !result.Success {
			return fmt.Errorf("validation failed or no credentials validated")
		}

		return nil
	},
}

var validateToolsStrict bool

var validateToolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "Check all tool dependencies",
	RunE: func(cmd *cobra.Command, args []string) error {
		allOK := true

		// Required tools
		for _, t := range utils.RequiredTools {
			p, err := exec.LookPath(t.Name)
			if err != nil {
				utils.StepFail(fmt.Sprintf("%s — not found (%s)", t.Name, t.Install))
				allOK = false
				continue
			}
			if validateToolsStrict && t.Flag != "" {
				ver := utils.RunCommandTimeout(10*time.Second, t.Name, []string{t.Flag})
				if ver.Success {
					utils.StepOk(fmt.Sprintf("%s  %s  %s", t.Name, utils.DimStyle.Render("≥"+t.MinVer), utils.MutedStyle.Render(p)))
				} else {
					utils.StepOk(fmt.Sprintf("%s  %s", t.Name, utils.MutedStyle.Render(p)))
				}
			} else {
				utils.StepOk(fmt.Sprintf("%s  %s", t.Name, utils.MutedStyle.Render(p)))
			}
		}

		// Optional tools
		for _, t := range utils.OptionalTools {
			if _, err := exec.LookPath(t.Name); err == nil {
				utils.StepOk(fmt.Sprintf("%s (optional)", t.Name))
			} else {
				utils.StepInfo(fmt.Sprintf("%s — not found (%s)", t.Name, t.Install))
			}
		}

		// Windows binaries
		exeDir := "exe"
		for _, b := range utils.WindowsBinaries {
			if _, err := os.Stat(exeDir + "/" + b.Name); err == nil {
				utils.StepOk(fmt.Sprintf("%s  %s", b.Name, utils.DimStyle.Render(b.Desc)))
			} else {
				utils.StepInfo(fmt.Sprintf("%s — not found in exe/ (%s)", b.Name, b.Desc))
			}
		}

		if !allOK {
			return fmt.Errorf("some required tools missing — run setup.sh or install manually")
		}
		utils.StepOk("All required tools available")
		return nil
	},
}

var validateConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Validate config file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if Cfg == nil {
			return fmt.Errorf("config not loaded")
		}
		if Cfg.DBPath == "" {
			utils.StepWarn("db_path is empty — using default")
		}
		utils.StepOk("config loaded successfully")
		return nil
	},
}

var validateSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Full setup validation",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateToolsCmd.RunE(cmd, args); err != nil {
			return err
		}
		return validateConfigCmd.RunE(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().StringVarP(&validateTarget, "target", "t", "", "Target host IP or hostname (validates against all hosts if not specified)")
	validateToolsCmd.Flags().BoolVar(&validateToolsStrict, "strict", false, "Check minimum versions of all tools")
	validateCmd.AddCommand(validateToolsCmd, validateConfigCmd, validateSetupCmd)
}
