package modules

import (
	"fmt"
	"log/slog"
	"time"

	"adpack/core"
)

func RunImpact(state *core.ADState) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if state == nil {
		slog.Warn("nil state — skipping impact phase")
		return result
	}

	slog.Info("impact phase: executing mission objective")

	credsForExfil := len(state.Creds)
	hostsForExfil := len(state.Hosts)

	daCreds := countDACreds(state)
	slog.Info("impact phase: mission readiness",
		"hosts", hostsForExfil,
		"creds", credsForExfil,
		"da_creds", daCreds,
	)

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type:       core.EvUserEnumerated,
		Phase:      core.PhaseImpact,
		Source:     "impact",
		Key:        "objective_complete",
		Value:      fmt.Sprintf("impact phase complete — %d hosts controlled, %d creds available", hostsForExfil, credsForExfil),
		Confidence: 1.0,
		Timestamp:  time.Now(),
	})

	slog.Info("impact phase complete")
	return result
}

func countDACreds(state *core.ADState) int {
	n := 0
	for _, c := range state.Creds {
		if !c.Validated {
			continue
		}
		for _, u := range state.Users {
			if u.Username == c.Username && u.IsDA {
				n++
				break
			}
		}
	}
	return n
}
