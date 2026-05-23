package dcsync

import (
	"context"
	"strings"

	"adpack/core"
)

// Executor implements the DCSync capability.
// Models DRSUAPI domain replication: given a GetChanges/GetChangesAll edge,
// replicates credential material and produces derived trust edges.
// Stress-tests: multiple identity observations, artifact emission,
// heavy graph mutation (multiple derived edges), partial failure modes.
type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "DCSync"
}

// CanExecute is pure with respect to ADState. Requires source, target, domain,
// and the edge AccessRight or Requires must indicate DCSync capability.
func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	if strings.EqualFold(edge.AccessRight, "DCSync") {
		return true
	}
	if strings.EqualFold(edge.AccessRight, "GetChanges") {
		return true
	}
	for _, r := range edge.Requires {
		if strings.EqualFold(r, "GetChanges") || strings.EqualFold(r, "GetChangesAll") {
			return true
		}
	}
	return false
}

// hasAllChanges checks whether the edge implies full replication rights
// (GetChangesAll). If the edge only has GetChanges (without All), the
// executor produces a partial result to stress-test partial failure mode.
func hasAllChanges(edge core.PrivilegeEdge) bool {
	if strings.EqualFold(edge.AccessRight, "DCSync") {
		return true
	}
	if strings.EqualFold(edge.AccessRight, "GetChangesAll") {
		return true
	}
	for _, r := range edge.Requires {
		if strings.EqualFold(r, "GetChangesAll") {
			return true
		}
	}
	return false
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	fullReplication := hasAllChanges(edge)

	identities := []core.IdentityObservation{
		{
			Type: "krbtgt_hash_inferred",
			Data: map[string]any{
				"source":      edge.SourcePrincipal,
				"domain":      edge.Domain,
				"target_dc":   edge.TargetPrincipal,
				"confidence":  0.7,
				"description": "krbtgt hash inferred via DRSUAPI replication",
			},
		},
		{
			Type: "domain_sid",
			Data: map[string]any{
				"domain":     edge.Domain,
				"source":     edge.SourcePrincipal,
				"confidence": 0.9,
			},
		},
	}

	artifacts := []core.ArtifactObservation{
		{
			Type: "replicated_secrets",
			Data: map[string]any{
				"source":           edge.SourcePrincipal,
				"target":           edge.TargetPrincipal,
				"domain":           edge.Domain,
				"object_count":     "142",
				"full_replication": fullReplication,
			},
		},
	}

	// Derived edges — trust relationships inferred from replication
	newEdges := []core.PrivilegeEdge{
		{
			SourcePrincipal: edge.SourcePrincipal,
			TargetPrincipal: "krbtgt",
			AccessRight:     "SIDHistory",
			EdgeType:        "domain_trust",
			Domain:          edge.Domain,
			Provenance:      "executor",
			Confidence:      0.8,
		},
	}

	// With full replication, produce a second derived edge (trust bridge)
	if fullReplication {
		newEdges = append(newEdges, core.PrivilegeEdge{
			SourcePrincipal: edge.SourcePrincipal,
			TargetPrincipal: edge.TargetPrincipal,
			AccessRight:     "GoldenTicket",
			EdgeType:        "credential_forge",
			Domain:          edge.Domain,
			Provenance:      "executor",
			Confidence:      0.85,
		})
	}

	failureMode := core.FailureSuccess
	if !fullReplication {
		// Partial replication — some objects replicated, but krbtgt hash
		// requires GetChangesAll. Graph partially updated, edge stays live.
		failureMode = core.FailurePartial
	}

	return core.ExecutionResult{
		FailureMode: failureMode,
		Delta: core.PostStateDelta{
			NewEdges: newEdges,
		},
		Identities: identities,
		Artifacts:  artifacts,
	}
}
