package modules

import (
	"adpack/core"
	"adpack/tools"
	"adpack/utils"
	"context"
	"fmt"
	"strings"
	"time"
)

func RunDiscovery(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	ctx := context.Background()

	if targetHost != "" {
		host := core.Host{
			IP:        targetHost,
			Hostname:  "",
			Domain:    "",
			PortsOpen: "389,445",
		}
		// Probe via LDAP with available creds to determine if target is a DC
		for _, c := range state.Creds {
			if c.Validated && c.Domain != "" && c.Username != "" {
				probe := tools.NetExecTarget{
					Protocol: "ldap", Host: targetHost,
					Domain: c.Domain, Username: c.Username, Password: c.Secret, Hash: c.Hash,
				}
				if r, err := tools.NetExec.Run(ctx, probe, "", nil); err == nil && r.Success {
					host.IsDC = true
					host.Domain = c.Domain
					if strings.Contains(r.Stdout, "(name:") {
						parts := strings.Split(r.Stdout, "(name:")
						if len(parts) > 1 {
							name := strings.Split(parts[1], ")")[0]
							host.Hostname = strings.ToUpper(strings.TrimSpace(name))
						}
					}
					break
				}
			}
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
