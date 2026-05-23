package certauth

import (
	"context"
	"strings"

	"adpack/core"
)

// Executor implements the CERT_AUTH capability.
// Models certificate-based authentication: validates cert context and
// produces a HasSession edge (native BH edge type the planner understands)
// plus a structured identity observation for the observation pipeline.
//
// This exercises the harder parts of the architecture:
//   - observation ingestion (identity observations with structured payloads)
//   - identity correlation (principal, UPN, auth_type)
//   - state mutation from non-ACL artifacts (cert-derived session edges)
//   - planner invalidation via ApplyDelta(changed)
//   - provenance layering beyond static BH edges (Provenance: "executor")
type Executor struct{}

func (e *Executor) Capability() core.Capability {
	return "CERT_AUTH"
}

// CanExecute is pure with respect to ADState. Validates source identity,
// target CA context, and template enrollment semantics.
func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	info := extractCertInfo(edge.Requires)
	if info == nil {
		return false
	}
	_, hasCA := info["CA"]
	_, hasTemplate := info["Template"]
	return hasCA || hasTemplate
}

// extractCertInfo parses certificate context from Requires.
// Format: "certificate:CN=value, Issuer=value, Template=value, CA=value, UPN=value"
func extractCertInfo(reqs []string) map[string]any {
	for _, r := range reqs {
		if !strings.HasPrefix(r, "certificate") {
			continue
		}
		info := make(map[string]any)
		rest := strings.TrimPrefix(r, "certificate")
		rest = strings.TrimPrefix(rest, ":")
		for _, part := range strings.Split(rest, ",") {
			part = strings.TrimSpace(part)
			k, v, ok := strings.Cut(part, "=")
			if ok {
				info[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		return info
	}
	return nil
}

func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	certInfo := extractCertInfo(edge.Requires)

	// Structured identity observation — feeds the observation pipeline
	// for future Kerberos/TGT materialization flows.
	identityObs := core.IdentityObservation{
		Type: "certificate_auth",
		Data: map[string]any{
			"principal": edge.SourcePrincipal,
			"domain":    edge.Domain,
		},
	}
	for k, v := range certInfo {
		identityObs.Data[strings.ToLower(k)] = v
	}
	if _, ok := identityObs.Data["upn"]; !ok {
		identityObs.Data["upn"] = edge.SourcePrincipal + "@" + edge.Domain
	}
	if _, ok := identityObs.Data["auth_type"]; !ok {
		identityObs.Data["auth_type"] = "pkinit"
	}

	// HasSession is a native BH edge type — the planner already
	// understands it and can traverse it in pathfinding.
	derivedEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "HasSession",
		EdgeType:        "cert",
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
	}
}
