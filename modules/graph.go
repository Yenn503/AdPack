package modules

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
)

func RunGraphAnalysis(ctx context.Context, provider core.DirectoryProvider) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	fmt.Println("[*] Enumerating computers...")
	computers, err := provider.EnumerateComputers(ctx)
	if err != nil {
		fmt.Printf("[!] Computer enumeration failed: %v\n", err)
	} else {
		result.Computers = append(result.Computers, computers...)
		for _, c := range computers {
			confidence := 0.85
			if c.IsDC {
				confidence = 0.95
			}
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvComputerEnumerated, Phase: core.PhaseGraphAnalysis,
				Source: "ldap", Key: c.Name + "@" + c.Domain,
				Value: c.OperatingSystem, Confidence: confidence,
				Timestamp: time.Now(),
			})
		}
		fmt.Printf("[+] %d computers enumerated\n", len(computers))
	}

	fmt.Println("[*] Enumerating GPOs...")
	gpos, err := provider.EnumerateGPOs(ctx)
	if err != nil {
		fmt.Printf("[!] GPO enumeration failed: %v\n", err)
	} else {
		result.GPOs = append(result.GPOs, gpos...)
		for _, g := range gpos {
			confidence := 0.9
			if g.GUID == "" {
				confidence = 0.5
			}
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvGPOEnumerated, Phase: core.PhaseGraphAnalysis,
				Source: "ldap", Key: g.Name + "@" + g.Domain,
				Value: g.GUID, Confidence: confidence,
				Timestamp: time.Now(),
			})
		}
		fmt.Printf("[+] %d GPOs enumerated\n", len(gpos))
	}

	fmt.Println("[*] Enumerating ADCS certificate templates...")
	templates, err := provider.EnumerateADCSTemplates(ctx)
	if err != nil {
		fmt.Printf("[!] ADCS enumeration failed: %v\n", err)
	} else {
		result.ADCS = append(result.ADCS, templates...)
		for _, t := range templates {
			confidence := 0.5
			if t.Vuln != "" {
				confidence = 0.9
			}
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvADCSEnumerated, Phase: core.PhaseGraphAnalysis,
				Source: "ldap", Key: t.Name + "@" + t.Domain,
				Value: t.Vuln, Confidence: confidence,
				Timestamp: time.Now(),
			})
		}
		fmt.Printf("[+] %d ADCS templates found\n", len(templates))
	}

	return result
}
