package adcs

import (
	"context"
	"strings"

	"adpack/core"
)

type ESC7Executor struct{}

func (e *ESC7Executor) Capability() core.Capability {
	return "ADCS_ESC7"
}

func (e *ESC7Executor) CanExecute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) bool {
	if !certipyAvailable() {
		return false
	}
	ar := strings.ToUpper(edge.AccessRight)
	return strings.Contains(ar, "ESC7") || strings.EqualFold(edge.EdgeType, "adcs_esc7")
}

func (e *ESC7Executor) Execute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "ADCS_ESC1",
				EdgeType:        "adcs_esc1",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.75,
			}},
		},
	}
}
