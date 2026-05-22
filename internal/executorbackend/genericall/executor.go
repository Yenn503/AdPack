package genericall

import (
	"context"

	"adpack/core"
)

// Executor implements the GenericAll capability.
// Given a GenericAll edge from source to target, it simulates adding the
// source principal to the target group, producing a MemberOf edge with
// executor provenance. This is intentionally minimal — validates the
// end-to-end contract without external dependencies.
type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "GenericAll"
}

// CanExecute is pure with respect to ADState. External probing is
// not required for this capability — the check is entirely local.
// Returns true when source and target are both specified in the edge.
func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return edge.SourcePrincipal != "" && edge.TargetPrincipal != ""
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	resultEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "MemberOf",
		EdgeType:        "acl",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      1.0,
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{resultEdge},
		},
		Identities: []core.IdentityObservation{
			{
				Type: "group_membership",
				Data: map[string]any{
					"source": edge.SourcePrincipal,
					"target": edge.TargetPrincipal,
					"domain": edge.Domain,
					"right":  "MemberOf",
				},
			},
		},
	}
}
