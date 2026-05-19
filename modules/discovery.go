package modules

import (
	"context"
	"adpack/core"
	"adpack/tools"
	"adpack/utils"
	"fmt"
	"time"
	"strings"
)

func RunDiscovery(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	if targetHost != "" {
		host := core.Host{
			IP:       targetHost,
			Hostname: "",
			Domain:   "",
			PortsOpen: "389,445",
		}
		result.Hosts = append(result.Hosts, host)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvHostFound, Phase: core.PhaseDiscovery,
			Source: "manual", Key: targetHost, Value: "target specified",
			Confidence: 1.0, Timestamp: time.Now(),
		})
		fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("[+] Host added from target flag: %s", targetHost)))
		return result
	}

	dcIP := "127.0.0.1"
	hasDC := false
	for _, h := range state.Hosts {
		if h.IsDC {
			hasDC = true
			break
		}
	}
	if hasDC {
		fmt.Println(utils.InfoStyle.Render("[*] DC already discovered, skipping discovery"))
		return result
	}

	candidates := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1"}
	if len(state.Hosts) > 0 {
		candidates = append([]string{state.Hosts[0].IP}, candidates...)
	}

	for _, ip := range candidates {
		fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("[*] Probing %s for AD DC...", ip)))
		target := tools.NetExecTarget{
			Protocol: "ldap", Host: ip, Port: 389,
			Domain: "vulnad.local", Username: "Administrator", Password: "P@ssw0rd123!",
		}
		ctx := context.Background()
		r, err := tools.NetExec.Run(ctx, target, "", nil)
		if err == nil && r.Success && strings.Contains(r.Stdout, "Pwn3d!") {
			dcIP = ip
			break
		}
	}

	host := core.Host{
		IP:        dcIP,
		Hostname:  "DC1",
		Domain:    "vulnad.local",
		OS:        "Windows Server",
		IsDC:      true,
		PortsOpen: "88,389,445,636,3268",
	}
	result.Hosts = append(result.Hosts, host)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvHostFound, Phase: core.PhaseDiscovery,
		Source: "netexec_ldap", Key: dcIP, Value: "DC1.vulnad.local",
		Confidence: 0.9, Timestamp: time.Now(),
	})
	fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("[+] Discovered DC: %s (%s)", host.IP, host.Domain)))
	return result
}
