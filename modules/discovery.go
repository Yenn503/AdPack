package modules

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
)

func RunDiscovery(state *core.ADState, targetHost string, cidrs []string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	ctx := context.Background()

	if targetHost == "" && len(state.Hosts) > 0 {
		slog.Debug("Hosts already discovered, skipping discovery")
		return result
	}

	// Phase 1: Add the explicit target host from CLI flag
	if targetHost != "" {
		host := probeHost(ctx, state, targetHost)
		result.Hosts = append(result.Hosts, host)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvHostFound, Phase: core.PhaseDiscovery,
			Source: "manual", Key: targetHost, Value: "target specified",
			Confidence: 1.0, Timestamp: time.Now(),
		})
		slog.Info("Host added from target flag", "host", targetHost)
	}

	// Phase 2: Subnet scan to discover additional hosts
	slog.Debug("Scanning subnet(s) for additional hosts...")
	subnets := cidrs
	if len(subnets) == 0 {
		if s := deriveSubnet(targetHost); s != "" {
			subnets = []string{s}
		}
	}
	for _, subnet := range subnets {
		discovered := nmapPingSweep(subnet)
		for _, ip := range discovered {
			// Skip already-known hosts (both result.Hosts and state.Hosts)
			alreadyKnown := false
			for _, h := range result.Hosts {
				if h.IP == ip {
					alreadyKnown = true
					break
				}
			}
			if !alreadyKnown {
				for _, h := range state.Hosts {
					if h.IP == ip {
						alreadyKnown = true
						break
					}
				}
			}
			if alreadyKnown {
				continue
			}
			h := probeHost(ctx, state, ip)
			result.Hosts = append(result.Hosts, h)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvHostFound, Phase: core.PhaseDiscovery,
				Source: "nmap_sweep", Key: ip, Value: h.Hostname,
				Confidence: 0.7, Timestamp: time.Now(),
			})
			slog.Info("Discovered host", "hostname", h.Hostname, "ip", ip)
		}
	}

	return result
}

func probeHost(ctx context.Context, state *core.ADState, ip string) core.Host {
	host := core.Host{
		IP:        ip,
		Hostname:  "",
		Domain:    "",
		PortsOpen: "389,445",
	}
	for _, c := range state.Creds {
		if c.Validated && c.Domain != "" && c.Username != "" {
			probe := tools.NetExecTarget{
				Protocol: "ldap", Host: ip,
				Domain: c.Domain, Username: c.Username, Password: c.Secret, Hash: c.Hash,
			}
			if r, err := tools.NetExec.Run(ctx, probe, "", nil); err == nil && r.Success {
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
			// Try SMB probe if LDAP fails
			probe.Protocol = "smb"
			if r, err := tools.NetExec.Run(ctx, probe, "", nil); err == nil && r.Success {
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
	// Fallback: try null session SMB probe
	if host.Hostname == "" {
		target := tools.NetExecTarget{
			Protocol: "smb", Host: ip,
			Domain: "", Username: "", Password: "",
		}
		if r, err := tools.NetExec.Run(ctx, target, "", nil); err == nil && r.Success {
			if strings.Contains(r.Stdout, "(name:") {
				parts := strings.Split(r.Stdout, "(name:")
				if len(parts) > 1 {
					name := strings.Split(parts[1], ")")[0]
					host.Hostname = strings.ToUpper(strings.TrimSpace(name))
				}
			}
		}
	}
	// DC detection via LDAP null-bind — real DCs respond with (domain:...) in banner
	ldapProbe := tools.NetExecTarget{
		Protocol: "ldap", Host: ip,
		Domain: "", Username: "", Password: "",
	}
	if lr, lerr := tools.NetExec.Run(ctx, ldapProbe, "", nil); lerr == nil && lr.Success && strings.Contains(lr.Stdout, "(domain:") {
		host.IsDC = true
		// Override domain with the actual AD domain from LDAP response
		for _, line := range strings.Split(lr.Stdout, "\n") {
			if strings.HasPrefix(line, "LDAP") && strings.Contains(line, "domain:") {
				parts := strings.SplitN(line, "(domain:", 2)
				if len(parts) > 1 {
					end := strings.Index(parts[1], ")")
					if end > 0 {
						host.Domain = strings.TrimSpace(parts[1][:end])
					}
				}
			}
		}
	}
	return host
}

func deriveSubnet(targetIP string) string {
	if targetIP == "" {
		return ""
	}
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}

func nmapPingSweep(subnet string) []string {
	cmd := exec.Command("nmap", "-sn", "-T4", "--host-timeout", "10s", subnet)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var ips []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Nmap scan report for") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if net.ParseIP(p) != nil {
					ips = append(ips, p)
				}
			}
		}
	}
	return ips
}
