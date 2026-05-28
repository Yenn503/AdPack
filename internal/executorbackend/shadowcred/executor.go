package shadowcred

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "SHADOW_CRED"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	if strings.Contains(right, "KEYCREDENTIAL") || strings.Contains(right, "SHADOW") {
		return true
	}
	return strings.EqualFold(edge.EdgeType, "shadowcred")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "PKINIT",
		EdgeType:        "shadowcred",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.85,
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{derivedEdge},
		},
		Identities: []core.IdentityObservation{
			{
				Type: "shadow_credential",
				Data: map[string]any{
					"source_principal": edge.SourcePrincipal,
					"target_principal": edge.TargetPrincipal,
					"domain":           edge.Domain,
					"action":           "add_keycredentiallink",
				},
			},
		},
	}
}
