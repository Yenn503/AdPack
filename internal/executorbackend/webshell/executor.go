package webshell

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "WEBSHELL_UPLOAD"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "WEBSHELL_UPLOAD")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "SeImpersonatePrivilege",
				EdgeType:        "webshell",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.7,
			}},
		},
	}
}
