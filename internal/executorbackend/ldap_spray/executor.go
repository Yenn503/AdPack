package ldap_spray

import (
	"context"
	"strings"

	"adpack/core"
)

type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "LDAP_SPRAY"
}

func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	if strings.Contains(right, "SPRAY") || strings.Contains(right, "PASSWORD") {
		return true
	}
	return strings.EqualFold(edge.EdgeType, "spray")
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "ValidCredential",
		EdgeType:        "spray",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.75,
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{derivedEdge},
		},
		Identities: []core.IdentityObservation{
			{
				Type: "validated_credential",
				Data: map[string]any{
					"source_principal": edge.SourcePrincipal,
					"target_principal": edge.TargetPrincipal,
					"domain":           edge.Domain,
					"action":           "ldap_password_spray",
				},
			},
		},
	}
}
