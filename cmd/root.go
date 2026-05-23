package cmd

import (
	"fmt"
	"os"
	"strings"

	"adpack/config"
	"adpack/core"
	"adpack/internal/executorbackend"
	"adpack/internal/executorbackend/addmember"
	"adpack/internal/executorbackend/asrep_roast"
	"adpack/internal/executorbackend/certauth"
	"adpack/internal/executorbackend/dcsync"
	"adpack/internal/executorbackend/forcechangepassword"
	"adpack/internal/executorbackend/genericall"
	"adpack/internal/executorbackend/kerberoast"
	"adpack/internal/executorbackend/ldap_spray"
	"adpack/internal/executorbackend/rbcd"
	"adpack/internal/executorbackend/shadowcred"
	"adpack/internal/executorbackend/writedacl"
	"adpack/internal/runtime"
	"adpack/modules"
	"adpack/storage"
	"adpack/utils"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	dbPath  string
	Cfg     *config.Config
	DB      *storage.DB
)

var version = "v0.1.0"

const BannerTemplate = `
    ___       ______             __  
   /   | ____/ / __ \____ ______/ /__
  / /| |/ __  / /_/ / __ ` + "`" + `/ ___/ //_/
 / ___ / /_/ / ____/ /_/ / /__/ ,<   
/_/  |_\__,_/_/    \__,_/\___/_/|_|  

Advanced AD Attack Orchestration Engine
Author: Jyenn
Version: %s
`

var rootCmd = &cobra.Command{
	Use:   "adpack",
	Short: "AD attack workflow orchestration engine",
	Long: utils.BannerStyle.Render(fmt.Sprintf(BannerTemplate, version)) + `
adpack tracks evidence across AD attack phases, detects gaps,
recommends next actions, and automates credential acquisition.

Workflow: discovery -> enumeration -> credential_acq -> session_harvest
                                           -> graph_analysis -> privesc
                                                            -> lateral -> persistence
         -> credential_acq -> validation`,
	Example: `  adpack status                    Show current state and gaps
  adpack next                     Show the recommended next phase
  adpack run credential_acq       Execute credential acquisition (default profile)
  adpack run credential_acq -e undefend -t 10.0.0.5
  adpack phases                   List all phases with status and dependencies
  adpack profiles                 List available evasion profiles
  adpack interactive              Launch the TUI dashboard
  adpack completion bash          Generate bash completion script`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "version" {
			return nil
		}
		if DB != nil {
			return nil
		}
		var err error
		Cfg, err = config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		p := dbPath
		if p == "" && Cfg.DBPath != "" {
			p = Cfg.DBPath
		}
		if p == "" {
			p = storage.DefaultPath()
		}
		DB, err = storage.Open(p)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func Execute() {
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	modules.ExecutorFactory = executorbackend.New
	modules.RuntimeFactory = func() core.RuntimeProvider {
		return runtime.NewSupervisor()
	}
	modules.CapabilityRegistry = core.NewCapabilityRegistry()
	modules.CapabilityRegistry.Register(&addmember.Executor{})
	modules.CapabilityRegistry.Register(&forcechangepassword.Executor{})
	modules.CapabilityRegistry.Register(&writedacl.Executor{})
	modules.CapabilityRegistry.Register(&genericall.Executor{})
	modules.CapabilityRegistry.Register(&certauth.Executor{})
	modules.CapabilityRegistry.Register(&dcsync.Executor{})
	modules.CapabilityRegistry.Register(&rbcd.Executor{})
	modules.CapabilityRegistry.Register(&shadowcred.Executor{})
	modules.CapabilityRegistry.Register(&kerberoast.Executor{})
	modules.CapabilityRegistry.Register(&asrep_roast.Executor{})
	modules.CapabilityRegistry.Register(&ldap_spray.Executor{})

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().StringVarP(&dbPath, "db", "d", "", "database path (default ~/.adpack/state.db)")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long:  "Output shell completion code for the specified shell. Useful for sourcing in .bashrc or .zshrc.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletion(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s (use bash, zsh, fish, powershell)", args[0])
			}
		},
	})

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of adpack",
		Run: func(cmd *cobra.Command, args []string) {
			jsonFlag, _ := cmd.Flags().GetBool("json")
			if jsonFlag {
				fmt.Printf(`{"version":"%s"}`+"\n", version)
			} else {
				fmt.Printf("adpack %s\n", version)
			}
		},
	}
	versionCmd.Flags().Bool("json", false, "Output version in JSON format")
	rootCmd.AddCommand(versionCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "phases",
		Short: "List all attack phases and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := DB.LoadState()
			if err != nil {
				return fmt.Errorf("load state: %w", err)
			}

			t := table.New().
				Border(lipgloss.RoundedBorder()).
				BorderStyle(lipgloss.NewStyle().Foreground(utils.ColorSecondary)).
				Headers("PHASE", "STATUS", "DEPENDENCIES").
				StyleFunc(func(row, col int) lipgloss.Style {
					switch {
					case row == 0:
						return lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary)
					case col == 1:
						return lipgloss.NewStyle().Bold(true)
					default:
						return utils.BaseStyle
					}
				})

			for _, p := range core.AllPhases {
				deps := p.Dependencies()
				depStr := "none"
				if len(deps) > 0 {
					var s []string
					for _, d := range deps {
						s = append(s, string(d))
					}
					depStr = strings.Join(s, ", ")
				}

				statusStr := "untouched"
				var statusStyle lipgloss.Style

				switch state.Phases[p] {
				case core.PhaseInProgress:
					statusStr = "in-progress"
					statusStyle = lipgloss.NewStyle().Foreground(utils.ColorWarning)
				case core.PhaseComplete:
					statusStr = "complete"
					statusStyle = lipgloss.NewStyle().Foreground(utils.ColorSuccess)
				case core.PhaseSkipped:
					statusStr = "skipped"
					statusStyle = lipgloss.NewStyle().Foreground(utils.ColorMuted)
				default:
					statusStyle = lipgloss.NewStyle().Foreground(utils.ColorMuted)
				}

				t.Row(string(p), statusStyle.Render(statusStr), depStr)
			}
			fmt.Println(t.Render())
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "profiles",
		Short: "List available evasion profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Available evasion profiles:")
			for _, name := range modules.ListProfiles() {
				p, ok := modules.LookupProfile(name)
				if !ok {
					continue
				}
				fmt.Printf("  %-12s %s\n", p.Name, p.Description)
			}
			return nil
		},
	})
}
