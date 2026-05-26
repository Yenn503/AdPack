package adcs

import (
	"context"

	"adpack/core"
)

type PKINITAuthExecutor struct{}

func (e *PKINITAuthExecutor) Capability() core.Capability {
	return PKINIT_AUTH
}

func (e *PKINITAuthExecutor) CanExecute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) bool {
	if !certipyAvailable() {
		return false
	}
	if isEdgeStale(edge) {
		return false
	}
	if edge.AccessRight != "HasCertificate" {
		return false
	}
	if edge.EdgeType != "adcs_cert" {
		return false
	}
	for _, r := range edge.Requires {
		if r == "has_pfx" {
			return true
		}
	}
	return false
}

func (e *PKINITAuthExecutor) Execute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) core.ExecutionResult {
	targetUPN := edge.TargetPrincipal

	identities := []core.IdentityObservation{
		{
			Type: "pkinit_authenticated",
			Data: map[string]any{
				"source":     edge.SourcePrincipal,
				"target":     targetUPN,
				"domain":     edge.Domain,
				"confidence": 0.9,
			},
		},
	}

	newEdges := []core.PrivilegeEdge{
		{
			SourcePrincipal: edge.SourcePrincipal,
			TargetPrincipal: targetUPN,
			AccessRight:     "HasTGT",
			EdgeType:        "pkinit_tgt",
			Domain:          edge.Domain,
			Provenance:      "executor",
			Confidence:      0.9,
		},
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: newEdges,
		},
		Identities: identities,
	}
}
