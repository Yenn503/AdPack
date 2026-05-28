package kerberoast

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "KERBEROAST"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	if strings.Contains(right, "SPN") || strings.Contains(right, "SERVICE") {
		return true
	}
	return strings.EqualFold(edge.EdgeType, "kerberoast")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "TGSHash",
		EdgeType:        "kerberoast",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.8,
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{derivedEdge},
		},
		Identities: []core.IdentityObservation{
			{
				Type: "kerberos_tgs_hash",
				Data: map[string]any{
					"source_principal": edge.SourcePrincipal,
					"target_principal": edge.TargetPrincipal,
					"domain":           edge.Domain,
					"action":           "get_user_spns",
				},
			},
		},
	}
}
