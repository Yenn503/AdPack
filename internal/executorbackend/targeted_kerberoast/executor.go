package targetedkerberoast

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "TARGETED_KERBEROAST"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "TARGETED_KERBEROAST") ||
		strings.EqualFold(edge.EdgeType, "targeted_kerberoast")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "KERBEROAST",
				EdgeType:        "kerberoast",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.7,
			}},
		},
	}
}
