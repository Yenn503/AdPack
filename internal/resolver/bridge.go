package resolver

import (
	"strings"

	"adpack/core"
)

// BuildDeltaFromResolved maps a resolved artifact to a PostStateDelta.
// This is a pure function — no side effects, no state mutation.
// The caller (AttachResolverPipeline) applies the delta through ApplyDelta,
// maintaining the single mutation gate invariant.
//
// Provenance is layered as "resolver:<capability>" so each resolver's
// output is traceable even when multiple resolvers emit the same edge type.
func BuildDeltaFromResolved(resolved *ResolvedArtifact, evt core.ServiceEvent) *core.PostStateDelta {
	if resolved == nil {
		return nil
	}

	capStr := strings.ToLower(resolved.Capability)
	provenance := "resolver:" + capStr

	name := resolved.Identity.Name
	domain := resolved.Identity.Domain
	if name == "" || domain == "" {
		return nil
	}

	var edge *core.PrivilegeEdge

	switch strings.ToUpper(resolved.Capability) {
	case "CERT_AUTH":
		// HasSession: principal (cert owner) → computer (session target)
		// BH-native edge type the planner already traverses.
		target := extractTarget(evt)
		if target == "" {
			target = domain + "\\Domain Controllers"
		}
		edge = &core.PrivilegeEdge{
			SourcePrincipal: name,
			TargetPrincipal: target,
			AccessRight:     "HasSession",
			EdgeType:        "cert",
			Domain:          domain,
			Provenance:      provenance,
			Confidence:      resolved.Confidence,
		}

	case "GENERIC_ALL":
		edge = &core.PrivilegeEdge{
			SourcePrincipal: name,
			TargetPrincipal: domain + "\\Domain Admins",
			AccessRight:     "GenericAll",
			EdgeType:        "resolved",
			Domain:          domain,
			Provenance:      provenance,
			Confidence:      resolved.Confidence,
		}
	}

	if edge == nil {
		return nil
	}

	return &core.PostStateDelta{
		NewEdges: []core.PrivilegeEdge{*edge},
	}
}

// extractTarget pulls the best target principal from a service event.
// Prefers explicit target fields, falls back to domain-level target.
func extractTarget(evt core.ServiceEvent) string {
	if t, ok := evt.Data["target_principal"].(string); ok && t != "" {
		return t
	}
	if t, ok := evt.Data["target"].(string); ok && t != "" {
		return t
	}
	return ""
}
