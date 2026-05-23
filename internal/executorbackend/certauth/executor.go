package certauth

import (
	"context"
	"strings"

	"adpack/core"
)

// Executor implements the CERT_AUTH capability.
// Models certificate-based authentication: given an edge with cert context,
// it produces an identity observation describing the authentication and a
// derived AuthenticatedAs edge. This validates observation pipeline flow
// and multi-step side effects — distinct from GenericAll's single-delta
// topology mutation.
type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "CERT_AUTH"
}

// CanExecute is pure with respect to ADState. Requires source, target, domain,
// and at least one Requires entry with a "certificate" prefix.
func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	return hasCertContext(edge.Requires)
}

// hasCertContext checks whether the Requires list contains a certificate
// context entry (prefixed with "certificate").
func hasCertContext(reqs []string) bool {
	for _, r := range reqs {
		if strings.HasPrefix(r, "certificate") {
			return true
		}
	}
	return false
}

// extractCertInfo pulls human-readable certificate fields from Requires.
// Format: "certificate:CN=value, Issuer=value, Thumbprint=value"
func extractCertInfo(reqs []string) map[string]any {
	info := make(map[string]any)
	for _, r := range reqs {
		if !strings.HasPrefix(r, "certificate") {
			continue
		}
		// Parse key=value pairs after "certificate:"
		rest := strings.TrimPrefix(r, "certificate")
		rest = strings.TrimPrefix(rest, ":")
		for _, part := range strings.Split(rest, ",") {
			part = strings.TrimSpace(part)
			k, v, ok := strings.Cut(part, "=")
			if ok {
				info[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return info
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	certInfo := extractCertInfo(edge.Requires)

	identityObs := core.IdentityObservation{
		Type: "certificate_auth",
		Data: map[string]any{
			"source": edge.SourcePrincipal,
			"target": edge.TargetPrincipal,
			"domain": edge.Domain,
		},
	}
	for k, v := range certInfo {
		identityObs.Data[k] = v
	}

	artifactObs := core.ArtifactObservation{
		Type: "authenticated_session",
		Data: map[string]any{
			"source":      edge.SourcePrincipal,
			"target":      edge.TargetPrincipal,
			"domain":      edge.Domain,
			"capability":  "CERT_AUTH",
			"auth_method": "certificate",
		},
	}

	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "AuthenticatedAs",
		EdgeType:        "auth",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.9,
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{derivedEdge},
		},
		Identities: []core.IdentityObservation{identityObs},
		Artifacts:  []core.ArtifactObservation{artifactObs},
	}
}
