package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"adpack/config"
	"adpack/core"
	"adpack/internal/cracker"
	"adpack/internal/executorbackend"
	"adpack/internal/executorbackend/adcs"
	"adpack/internal/executorbackend/addmember"
	"adpack/internal/executorbackend/asrep_roast"
	"adpack/internal/executorbackend/certauth"
	"adpack/internal/executorbackend/dcsync"
	"adpack/internal/executorbackend/forcechangepassword"
	"adpack/internal/executorbackend/genericall"
	"adpack/internal/executorbackend/kerberoast"
	krbrelayup "adpack/internal/executorbackend/krb_relay_up"
	"adpack/internal/executorbackend/ldap_spray"
	"adpack/internal/executorbackend/mssql"
	"adpack/internal/executorbackend/rbcd"
	"adpack/internal/executorbackend/s4u_delegation"
	"adpack/internal/executorbackend/shadowcred"
	targetedkerberoast "adpack/internal/executorbackend/targeted_kerberoast"
	"adpack/internal/executorbackend/unconstrained_delegation"
	"adpack/internal/executorbackend/webshell"
	"adpack/internal/executorbackend/writedacl"
	"adpack/internal/runtime"
	"adpack/internal/transport/local"
	"adpack/internal/transport/proxy"
	slivertransport "adpack/internal/transport/sliver"
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

	crackQueue  *cracker.HashQueue
	crackWorker *cracker.CrackWorker
	crackMat    *cracker.CredentialMaterializer

	// Cracker CLI flags
	hashcatPathFlag string
	wordlistFlag    string
	rulesFlag       string
	crackTimeoutF   int
	verboseLogging  bool
	logDirFlag      string
)

var (
	version = "v0.6.0"
	rootCtx context.Context
	cancel  context.CancelFunc
)

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
  adpack run credential_acq -e native --target 10.0.0.5
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
		utils.InitLogging(logDirFlag, verboseLogging)
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

		// Signal handler for graceful shutdown
		rootCtx, cancel = context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			select {
			case <-sigCh:
				fmt.Fprintf(os.Stderr, "\n[!] Interrupt received — shutting down...\n")
				cancel()
			case <-rootCtx.Done():
			}
			signal.Stop(sigCh)
		}()

		modules.LootDir = Cfg.LootDir

		if crackQueue == nil {
			crackQueue = cracker.NewHashQueue()

			hashcatPath := Cfg.Cracking.HashcatPath
			wordlist := Cfg.Cracking.Wordlist
			rules := Cfg.Cracking.Rules
			timeout := time.Duration(Cfg.Cracking.Timeout) * time.Second
			if hashcatPathFlag != "" {
				hashcatPath = hashcatPathFlag
			}
			if wordlistFlag != "" {
				wordlist = wordlistFlag
			}
			if rulesFlag != "" {
				rules = strings.Split(rulesFlag, ",")
			}
			if crackTimeoutF > 0 {
				timeout = time.Duration(crackTimeoutF) * time.Second
			}

			crackWorker = cracker.NewCrackWorker(crackQueue, hashcatPath, wordlist, rules, timeout)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "[!] crackWorker panic: %v\n", r)
					}
				}()
				crackWorker.Run()
			}()
			crackMat = cracker.NewCredentialMaterializer(crackQueue, func(cred cracker.CrackedCredential) {
				utils.StepOk(fmt.Sprintf("🔓 CRACKED %s\\%s → %s", cred.Domain, cred.Username, cred.Secret))
				// Use CredHash type so the UPSERT matches the original hash credential row
				// (Conflicts on type+username+domain+target: CredHash matches AS-REP/Kerberoast/NTLM hashes).
				// The trust-preserving UPSERT keeps Validated=true and overwrites Secret with the plaintext.
				DB.SaveCred(core.Credential{
					Type:      core.CredHash,
					Username:  cred.Username,
					Domain:    cred.Domain,
					Secret:    cred.Secret,
					Hash:      cred.Hash,
					Source:    "cracker",
					Validated: true,
				})
			})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "[!] crackMat panic: %v\n", r)
					}
				}()
				crackMat.Run()
			}()
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
	defer utils.CloseLogging()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	modules.ExecutorFactory = executorbackend.New
	modules.TransportFactory = func(target core.HostRef, domain, user, pass, hash string) core.Transport {
		if Cfg == nil {
			slog.Warn("TransportFactory: Cfg is nil, using default transport")
			return local.New(target, domain, user, pass, hash)
		}
		mode := Cfg.Transport
		if mode == "" {
			mode = os.Getenv("ADPACK_TRANSPORT")
		}
		switch mode {
		case "sliver":
			return slivertransport.New(Cfg.Sliver.ConfigPath, Cfg.Sliver.ServerAddr)
		default:
			proxyAddr := Cfg.ProxyAddress
			if proxyAddr == "" {
				proxyAddr = os.Getenv("ADPACK_PROXY")
			}
			if proxyAddr != "" {
				return proxy.New(target, domain, user, pass, hash, proxyAddr)
			}
			return local.New(target, domain, user, pass, hash)
		}
	}
	modules.RuntimeFactory = func() core.RuntimeProvider {
		return runtime.NewSupervisor()
	}
	modules.CapabilityRegistry = core.NewCapabilityRegistry()
	modules.EnqueueHash = func(hashType, hash, username, domain string) {
		if crackQueue == nil {
			return
		}
		var typ cracker.HashType
		switch hashType {
		case "krb5tgs":
			typ = cracker.HashKRB5TGS
		case "krb5asrep":
			typ = cracker.HashKRB5ASREP
		case "ntlm":
			typ = cracker.HashNTLM
		default:
			return
		}
		crackQueue.Enqueue(&cracker.CrackJob{
			HashType: typ,
			Hash:     hash,
			Username: username,
			Domain:   domain,
			Priority: cracker.PriorityOther,
		})
	}
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
	modules.CapabilityRegistry.Register(&unconstrained_delegation.Executor{})
	modules.CapabilityRegistry.Register(&s4u_delegation.Executor{})
	modules.CapabilityRegistry.Register(&adcs.CertEnrollExecutor{})
	modules.CapabilityRegistry.Register(&adcs.PKINITAuthExecutor{})
	modules.CapabilityRegistry.Register(&mssql.ImpersonateExecutor{})
	modules.CapabilityRegistry.Register(&mssql.SysadminExecutor{})
	modules.CapabilityRegistry.Register(&mssql.XPCMDShellExecutor{})
	modules.CapabilityRegistry.Register(&mssql.UserImpersonateExecutor{})
	modules.CapabilityRegistry.Register(&mssql.NTLMCoerceExecutor{})
	modules.CapabilityRegistry.Register(&mssql.LinkedServerExecutor{})
	modules.CapabilityRegistry.Register(&adcs.ESC4Executor{})
	modules.CapabilityRegistry.Register(&adcs.ESC7Executor{})
	modules.CapabilityRegistry.Register(&targetedkerberoast.Executor{})
	modules.CapabilityRegistry.Register(&krbrelayup.Executor{})
	modules.CapabilityRegistry.Register(&webshell.Executor{})

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().StringVarP(&dbPath, "db", "d", "", "database path (default ~/.adpack/state.db)")
	rootCmd.PersistentFlags().BoolVarP(&verboseLogging, "verbose", "v", false, "enable verbose diagnostic logging")
	rootCmd.PersistentFlags().StringVar(&logDirFlag, "log-dir", "", "write structured JSON logs to this directory")
	rootCmd.PersistentFlags().StringVar(&hashcatPathFlag, "hashcat-path", "", "path to hashcat binary (overrides config)")
	rootCmd.PersistentFlags().StringVar(&wordlistFlag, "wordlist", "", "path to wordlist (overrides config)")
	rootCmd.PersistentFlags().StringVar(&rulesFlag, "rules", "", "comma-separated hashcat rule files (overrides config)")
	rootCmd.PersistentFlags().IntVar(&crackTimeoutF, "crack-timeout", 0, "timeout in seconds per hash (overrides config)")

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
				case core.PhaseFailed:
					statusStr = "failed"
					statusStyle = lipgloss.NewStyle().Foreground(utils.ColorError)
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

	rootCmd.AddCommand(&cobra.Command{
		Use:   "loot",
		Short: "Display comprehensive loot summary from current state",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := DB.LoadState()
			if err != nil {
				return fmt.Errorf("load state: %w", err)
			}
			modules.PrintLootSummary(state)
			fmt.Println()
			modules.PrintVulnCoverage(modules.AssessVulnCoverage(state))
			fmt.Println()
			return nil
		},
	})
}
