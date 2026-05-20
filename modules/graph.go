package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
)

func RunGraphAnalysis(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target for graph analysis")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for graph analysis")
		result.Success = false
		return result
	}

	ctx := context.Background()
	target := tools.NetExecTarget{
		Protocol: "ldap", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Println("[*] Enumerating computers via LDAP...")
	r, err := tools.NetExec.Run(ctx, target, "--computers", []string{})
	if err == nil && r.Success {
		computers := parseComputers(r.Stdout, domain)
		result.Computers = append(result.Computers, computers...)
		for _, c := range computers {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvUserEnumerated, Phase: core.PhaseGraphAnalysis,
				Source: "ldap", Key: c.Name + "@" + c.Domain, Value: c.OperatingSystem,
				Timestamp: time.Now(),
			})
		}
		fmt.Printf("[+] %d computers enumerated\n", len(computers))
	}

	fmt.Println("[*] Enumerating GPOs via LDAP...")
	r, err = tools.NetExec.Run(ctx, target, "-M", []string{"gpolocal"})
	if err == nil && r.Success {
		gpos := parseGPOs(r.Stdout, domain)
		result.GPOs = append(result.GPOs, gpos...)
		for _, g := range gpos {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvUserEnumerated, Phase: core.PhaseGraphAnalysis,
				Source: "ldap", Key: g.Name + "@" + g.Domain, Value: g.GUID,
				Timestamp: time.Now(),
			})
		}
		fmt.Printf("[+] %d GPOs enumerated\n", len(gpos))
	}

	fmt.Println("[*] Enumerating ADCS certificate templates...")
	r, err = tools.NetExec.Run(ctx, target, "-M", []string{"adcs"})
	if err == nil && r.Success {
		templates := parseADCSTemplates(r.Stdout, domain)
		result.ADCS = append(result.ADCS, templates...)
		for _, t := range templates {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvUserEnumerated, Phase: core.PhaseGraphAnalysis,
				Source: "ldap", Key: t.Name + "@" + t.Domain, Value: t.Vuln,
				Timestamp: time.Now(),
			})
		}
		fmt.Printf("[+] %d ADCS templates found\n", len(templates))
	}

	return result
}

func parseComputers(output, domain string) []core.Computer {
	var computers []core.Computer
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "|") {
			continue
		}
		if !strings.Contains(line, "$") && !strings.HasSuffix(line, "$") {
			continue
		}
		name := strings.Fields(line)[0]
		name = strings.TrimSuffix(name, "$")
		computers = append(computers, core.Computer{
			Name: name, Domain: domain, IsDC: strings.Contains(strings.ToLower(line), "server"),
		})
	}
	return computers
}

func parseGPOs(output, domain string) []core.GPO {
	var gpos []core.GPO
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "|") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			gpos = append(gpos, core.GPO{
				Name: parts[0], GUID: parts[1], Domain: domain,
			})
		}
	}
	return gpos
}

func parseADCSTemplates(output, domain string) []core.ADCSTemplate {
	var templates []core.ADCSTemplate
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "[") {
			continue
		}
		templates = append(templates, core.ADCSTemplate{
			Name: line, Domain: domain,
		})
	}
	return templates
}
