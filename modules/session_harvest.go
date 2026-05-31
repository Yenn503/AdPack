package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"adpack/core"
	"adpack/utils"
)

func RunSessionHarvest(ctx context.Context, provider core.DirectoryProvider, state *core.ADState) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	utils.Section("🪪", "Session Harvest", "user session enumeration")
	for _, h := range state.Hosts {
		utils.Attempt("🪪", h.IP, "querying sessions via SMB")
	}

	slog.Debug("Harvesting sessions...")
	sessions, err := provider.EnumerateSessions(ctx)
	if err != nil {
		slog.Warn("Session harvest failed", "error", err)
		utils.StepWarn(fmt.Sprintf("Session harvest failed: %s", err))
		result.Success = false
		return result
	}

	userLookup := make(map[string]int)
	for _, u := range state.Users {
		key := strings.ToLower(u.Domain + `\` + u.Username)
		if u.ID > 0 {
			userLookup[key] = u.ID
		}
	}
	hostLookup := make(map[string]int)
	for _, h := range state.Hosts {
		if h.ID > 0 {
			hostLookup[h.IP] = h.ID
		}
	}

	// Build a host-IP → domain map for per-session fallback domain
	// resolution. Each session is resolved against the domain of its
	// own target host, preventing cross-domain bias in multi-forest
	// environments.
	hostDomain := make(map[string]string)
	for _, h := range state.Hosts {
		if h.IP != "" && h.Domain != "" {
			hostDomain[h.IP] = h.Domain
		}
	}

	// Identity drift snapshot: structured counters that turn per-session
	// resolution outcomes into a distributional signal. Every harvest run
	// produces one snapshot for cross-run comparison.
	type driftStats struct {
		Resolved          int `json:"resolved"`
		Unresolved        int `json:"unresolved"`
		MachineAccounts   int `json:"machine_accounts"`
		DomainMismatches  int `json:"domain_mismatches"`
		DuplicateHostRefs int `json:"duplicate_host_refs"`
		TotalSessions     int `json:"total_sessions"`
	}
	var stats driftStats
	seenRefs := make(map[string]string)

	for i := range sessions {
		stats.TotalSessions++
		sessions[i].Source = "nxc-smb-sessions"

		if uid, ok := userLookup[strings.ToLower(sessions[i].Username)]; ok {
			sessions[i].UserID = uid
		}
		if hid, ok := hostLookup[sessions[i].Host]; ok {
			sessions[i].HostID = hid
		}

		// Identity convergence probe: project session username onto the
		// canonical HostRef space. Resolved machine accounts confirm cross-
		// observation alignment; unresolved entries surface drift.
		// The fallback domain is derived from the session's own target host
		// IP to avoid cross-domain bias in multi-forest environments.
		sessionDomain := hostDomain[sessions[i].Host]
		if ref, ok := core.ResolveSessionRef(sessions[i].Username, sessionDomain); ok {
			stats.Resolved++
			stats.MachineAccounts++
			slog.Info("host identity resolved", "username", sessions[i].Username, "name", ref.Name, "domain", ref.Domain)

			// Track duplicate and mismatch: each iteration of the same
			// HostRef in one run is a compression opportunity; each
			// domain disagreement is a convergence fracture.
			refKey := ref.Name + "@" + ref.Domain
			if firstHost, dup := seenRefs[refKey]; dup {
				stats.DuplicateHostRefs++
				slog.Warn("duplicate hostref", "ref", refKey, "first_host", firstHost, "current_host", sessions[i].Host)
			} else {
				seenRefs[refKey] = sessions[i].Host
			}
			if ref.Domain != sessionDomain {
				stats.DomainMismatches++
				slog.Warn("domain mismatch", "resolved", ref.Domain, "session_domain", sessionDomain)
			}
		} else {
			stats.Unresolved++
			slog.Debug("user session (non-machine)", "username", sessions[i].Username)
		}

		confidence := 0.6
		if sessions[i].SourceIP != "" {
			confidence = 0.85
		}
		if sessions[i].UserID > 0 {
			confidence += 0.1
		}
		if confidence > 1.0 {
			confidence = 1.0
		}

		result.Sessions = append(result.Sessions, sessions[i])
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type:       core.EvSessionFound,
			Phase:      core.PhaseSessionHarvest,
			Source:     "nxc-smb-sessions",
			Key:        sessions[i].Username,
			Value:      sessions[i].Host,
			Timestamp:  time.Now(),
			Confidence: confidence,
		})
	}

	snapshot, _ := json.Marshal(stats)
	slog.Info("Identity drift snapshot", "snapshot", string(snapshot))
	slog.Info("Harvested sessions", "count", len(result.Sessions))
	utils.StepOk(fmt.Sprintf("Harvested %d session(s)", len(result.Sessions)))
	return result
}
