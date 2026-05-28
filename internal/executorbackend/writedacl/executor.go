package writedacl

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "WRITE_DACL"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	return right == "WRITEDACL" || right == "WRITEOWNER"
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "GenericAll",
		EdgeType:        "acl",
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
				Type: "dacl_modified",
				Data: map[string]any{
					"source_principal": edge.SourcePrincipal,
					"target":           edge.TargetPrincipal,
					"domain":           edge.Domain,
					"action":           "write_dacl",
				},
			},
		},
	}
}
