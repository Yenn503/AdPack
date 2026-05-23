package addmember

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "ADD_MEMBER"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	return right == "ADDMEMBER" || right == "ADDSELF"
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "MemberOf",
		EdgeType:        "acl",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.9,
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{derivedEdge},
		},
		Identities: []core.IdentityObservation{
			{
				Type: "group_member_added",
				Data: map[string]any{
					"principal": edge.SourcePrincipal,
					"group":     edge.TargetPrincipal,
					"domain":    edge.Domain,
					"action":    "add_member",
				},
			},
		},
	}
}
