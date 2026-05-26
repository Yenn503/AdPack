// Package unconstrained_delegation implements the UNCONSTRAINED_DELEGATION
// capability executor.
//
// Background: a principal flagged TRUSTED_FOR_DELEGATION (typically a
// computer account) caches the TGT of every user that authenticates to it.
// Once an attacker compromises that principal — or any principal with
// GenericAll/GenericWrite over it — the canonical exploit chain is:
//
//  1. Coerce a high-value account (DC machine account, DA user) into
//     authenticating to the unconstrained-delegation host via PrinterBug
//     (MS-RPRN), PetitPotam (MS-EFSRPC), or DFSCoerce (MS-DFSNM).
//  2. The captured authentication leaves a forwarded TGT in the
//     attacker-controlled host's LSASS or krbrelayx loot dir.
//  3. The attacker uses that TGT against the DC to DCSync the directory,
//     yielding krbtgt and full domain compromise.
//
// AdPack's runtime supervisor already manages the coercer + ntlmrelay +
// responder services that capture the TGT (see internal/runtime/). This
// executor's role in the capability execution contract is twofold:
//
//   - Execute() declares the derived edges the graph gains after a
//     successful exploit (DCSync on the DC + krbtgt access).
//   - dispatchTool wires a real secretsdump invocation that consumes
//     a previously captured ticket via KRB5CCNAME, so reconciliation can
//     confirm or degrade confidence based on actual output.
package unconstrained_delegation

import (
	"context"
	"strings"

	"adpack/core"
)

// Executor implements core.CapabilityExecutor for UNCONSTRAINED_DELEGATION.
type Executor struct{}

// Capability returns the canonical capability string.
func (e *Executor) Capability() core.Capability {
	return "UNCONSTRAINED_DELEGATION"
}

// CanExecute returns true when the edge declares an unconstrained
// delegation relationship and minimum graph metadata is present.
//
// Accepted forms:
//   - AccessRight contains "UNCONSTRAINED" (case-insensitive)
//   - AccessRight is "TRUSTED_FOR_DELEGATION" / "TRUSTED_TO_AUTH_FOR_DELEGATION"
//     when the variant flag is unconstrained
//   - EdgeType == "delegation" combined with AccessRight matching above
func (e *Executor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	if edge.SourcePrincipal == "" || edge.TargetPrincipal == "" || edge.Domain == "" {
		return false
	}
	right := strings.ToUpper(edge.AccessRight)
	if strings.Contains(right, "UNCONSTRAINED") {
		return true
	}
	// TRUSTED_FOR_DELEGATION is the LDAP attribute name; some collectors
	// surface it raw rather than translating to UNCONSTRAINED_DELEGATION.
	if right == "TRUSTED_FOR_DELEGATION" {
		return true
	}
	return false
}

// Execute declares the post-exploitation graph state. Per the contract:
//   - This function is PURE with respect to ADState (no mutation, no I/O).
//   - All derived edges carry Provenance="executor".
//   - Confidence reflects the deterministic nature of the exploit chain
//     given the precondition (coerced authentication) is met.
//
// Derived edges:
//
//   - SourcePrincipal → DC machine account → DCSync
//     once the TGT lands, the attacker can act as the DC, which holds
//     the GetChanges/GetChangesAll right inherently.
//   - SourcePrincipal → krbtgt → GoldenTicket
//     post-DCSync the attacker has the krbtgt hash, enabling ticket
//     forging — the persistence module consumes this edge.
func (e *Executor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	target := edge.TargetPrincipal

	// Edge: source can act as the DC (DCSync via captured TGT)
	dcSyncEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: target,
		AccessRight:     "DCSync",
		EdgeType:        "dcsync",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.85,
		Exploitability:  0.9,
		Noise:           0.6, // coercion + relay is detectable
		Requires:        []string{"coercer", "ntlmrelayx", "captured_tgt"},
	}

	// Edge: source can forge tickets (Golden Ticket via krbtgt hash)
	goldenEdge := core.PrivilegeEdge{
		SourcePrincipal: edge.SourcePrincipal,
		TargetPrincipal: "krbtgt",
		AccessRight:     "GoldenTicket",
		EdgeType:        "credential_forge",
		Domain:          edge.Domain,
		Provenance:      "executor",
		Confidence:      0.85,
		Exploitability:  0.95,
		Noise:           0.4,
		Requires:        []string{"impacket-ticketer"},
	}

	identities := []core.IdentityObservation{
		{
			Type: "unconstrained_delegation_principal",
			Data: map[string]any{
				"principal":   edge.SourcePrincipal,
				"domain":      edge.Domain,
				"delegate_to": "any_service_in_domain",
				"description": "TRUSTED_FOR_DELEGATION flag set; caches forwarded TGTs in LSASS",
			},
		},
	}

	artifacts := []core.ArtifactObservation{
		{
			Type: "captured_tgt_expected",
			Data: map[string]any{
				"loot_path_hint": "/tmp/krbrelayx-loot/*.ccache",
				"impersonated":   "victim",
				"target_for_use": "DCSync against " + edge.Domain,
			},
		},
	}

	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{dcSyncEdge, goldenEdge},
		},
		Identities: identities,
		Artifacts:  artifacts,
	}
}
