package forcechangepassword

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "FORCE_CHANGE_PASSWORD"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	return strings.EqualFold(edge.AccessRight, "ForceChangePassword")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "GenericAll",
		EdgeType:        "acl",
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
				Type: "password_reset",
				Data: map[string]any{
					"principal": edge.SourcePrincipal,
					"target":    edge.TargetPrincipal,
					"domain":    edge.Domain,
					"action":    "force_change_password",
				},
			},
		},
	}
}
