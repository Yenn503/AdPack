package modules

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
	"adpack/utils"
)

func RunGraphAnalysis(ctx context.Context, provider core.DirectoryProvider) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	utils.Section("🕸️", "Graph Analysis", "BloodHound power path discovery")
	utils.StepInfo("Enumerating computers from LDAP...")
	computers, err := provider.EnumerateComputers(ctx)
	if err != nil {
		utils.StepWarn(fmt.Sprintf("Computer enumeration failed: %v", err))
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
		utils.StepOk(fmt.Sprintf("%d computers enumerated", len(computers)))
		utils.Finding("Computers", fmt.Sprintf("%d machines found", len(computers)))
	}

	utils.StepInfo("Enumerating GPOs from LDAP...")
	gpos, err := provider.EnumerateGPOs(ctx)
	if err != nil {
		utils.StepWarn(fmt.Sprintf("GPO enumeration failed: %v", err))
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
		utils.StepOk(fmt.Sprintf("%d GPOs enumerated", len(gpos)))
		utils.Finding("GPOs", fmt.Sprintf("%d policies found", len(gpos)))
	}

	utils.StepInfo("Enumerating ADCS certificate templates...")
	templates, err := provider.EnumerateADCSTemplates(ctx)
	if err != nil {
		utils.StepWarn(fmt.Sprintf("ADCS enumeration failed: %v", err))
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
		utils.StepOk(fmt.Sprintf("%d ADCS templates found", len(templates)))
		utils.Finding("ADCS Templates", fmt.Sprintf("%d certificate templates", len(templates)))
	}

	utils.StepOk("Graph analysis complete")
	return result
}
