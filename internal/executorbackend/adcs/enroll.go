package adcs

import (
	"context"
	"strings"

	"adpack/core"
)

type CertEnrollExecutor struct{}

func (e *CertEnrollExecutor) Capability() core.Capability {
	return CERT_ENROLL
}

func (e *CertEnrollExecutor) CanExecute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) bool {
	if !certipyAvailable() {
		return false
	}
	if isEdgeStale(edge) {
		return false
	}
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" {
		return false
	}
	ar := strings.ToUpper(edge.AccessRight)
	if strings.Contains(ar, "ESC1") || strings.Contains(ar, "ESC13") {
		return true
	}
	for _, r := range edge.Requires {
		ru := strings.ToUpper(r)
		if strings.Contains(ru, "ESC1") || strings.Contains(ru, "ESC13") {
			return true
		}
	}
	return false
}

func (e *CertEnrollExecutor) Execute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) core.ExecutionResult {
	templateName := "ESC1"

	identities := []core.IdentityObservation{
		{
			Type: "cert_enrolled",
			Data: map[string]any{
				"source":     edge.SourcePrincipal,
				"target":     edge.TargetPrincipal,
				"domain":     edge.Domain,
				"template":   templateName,
				"confidence": 0.8,
			},
		},
	}

	newEdges := []core.PrivilegeEdge{
		{
			SourcePrincipal: edge.SourcePrincipal,
			TargetPrincipal: edge.TargetPrincipal,
			AccessRight:     "HasCertificate",
			EdgeType:        "adcs_cert",
			Domain:          edge.Domain,
			Provenance:      "executor",
			Confidence:      0.85,
			Requires:        []string{"has_pfx", "template:" + templateName},
		},
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: newEdges,
		},
		Identities: identities,
		Artifacts: []core.ArtifactObservation{
			{
				Type: "pfx_generated",
				Data: map[string]any{
					"template":  templateName,
					"source":    edge.SourcePrincipal,
					"target_ca": edge.TargetPrincipal,
				},
			},
		},
	}
}
