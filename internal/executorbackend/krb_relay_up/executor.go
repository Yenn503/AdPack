package krbrelayup

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "KRB_RELAY_UP"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "KRB_RELAY_UP") ||
		strings.EqualFold(edge.EdgeType, "krb_relay_up")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	target := edge.TargetPrincipal
	if target == "" {
		return core.ExecutionResult{FailureMode: core.FailureDeadEnd}
	}
	if strings.Contains(target, "@") {
		target = "SYSTEM@" + target[strings.LastIndex(target, "@")+1:]
	} else {
		target = "SYSTEM@" + target
	}
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: target,
				AccessRight:     "SYSTEM",
				EdgeType:        "krb_relay_up",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.7,
			}},
		},
	}
}
