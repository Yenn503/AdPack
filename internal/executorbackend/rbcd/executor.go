package rbcd

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "RBCD"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	if strings.Contains(right, "ALLOWEDTOACT") || strings.Contains(right, "RBCD") {
		return true
	}
	return strings.EqualFold(edge.EdgeType, "rbcd")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "AllowedToActOnBehalfOfOtherIdentity",
		EdgeType:        "rbcd",
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
				Type: "rbcd_delegation",
				Data: map[string]any{
					"source_principal": edge.SourcePrincipal,
					"target_principal": edge.TargetPrincipal,
					"domain":           edge.Domain,
					"action":           "set_rbcd",
				},
			},
		},
	}
}
