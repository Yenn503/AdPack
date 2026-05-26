package core

import (
	"context"
	"fmt"
	"strings"
)

// Capability matches AccessRight on a PrivilegeEdge.
type Capability string

// EdgeKey is a deterministic, unique key for a PrivilegeEdge.
type EdgeKey string

// EdgeKeyOf constructs a collision-free canonical key for an edge using
// null-byte separators (which cannot appear in AD principal names).
func EdgeKeyOf(e PrivilegeEdge) EdgeKey {
	return EdgeKey(fmt.Sprintf("%s\x00%s\x00%s\x00%s", e.Domain, e.SourcePrincipal, e.TargetPrincipal, e.AccessRight))
}

// CapabilityResolutionStatus tells the planner why an executor wasn't found.
type CapabilityResolutionStatus int

const (
	CapabilityAvailable CapabilityResolutionStatus = iota
	CapabilityUnimplemented
	CapabilityDisabled
)

// StateMutation tracks graph version for planner cache invalidation.
type StateMutation struct {
	Version uint64
}

// IdentityObservation avoids leaking resolver types into the execution layer.
type IdentityObservation struct {
	Type string
	Data map[string]any
}

// ArtifactObservation avoids leaking resolver types into the execution layer.
type ArtifactObservation struct {
	Type string
	Data map[string]any
}

// FailureMode classifies execution outcomes.
type FailureMode string

const (
	FailureSuccess   FailureMode = "success"
	FailureRetryable FailureMode = "retryable"
	FailureDeadEnd   FailureMode = "dead_end"
	FailurePartial   FailureMode = "partial"
)

// PostStateDelta separates mutation intent from application.
type PostStateDelta struct {
	NewEdges     []PrivilegeEdge
	RemovedEdges []EdgeKey
}

// ExecutionResult is the single output type for capability executors.
type ExecutionResult struct {
	Delta       PostStateDelta
	FailureMode FailureMode
	Identities  []IdentityObservation
	Artifacts   []ArtifactObservation
}

func (r ExecutionResult) Success() bool { return r.FailureMode == FailureSuccess }

// CapabilityExecutor is the pluggable backend for one Capability.
type CapabilityExecutor interface {
	Capability() Capability
	CanExecute(ctx context.Context, edge PrivilegeEdge, state *ADState) bool
	Execute(ctx context.Context, edge PrivilegeEdge, state *ADState) ExecutionResult
}

// CapabilityRegistry is a lookup-only registry.
type CapabilityRegistry struct {
	executors map[Capability]CapabilityExecutor
}

func NewCapabilityRegistry() *CapabilityRegistry {
	return &CapabilityRegistry{executors: make(map[Capability]CapabilityExecutor)}
}

func (r *CapabilityRegistry) Register(exec CapabilityExecutor) {
	r.executors[exec.Capability()] = exec
}

// AccessRightToCapability maps a privilege edge to the capability
// that can execute it. This is the central dispatch function that
// makes the planner→executor translation deterministic.
const ADCS_CERT_ENROLL Capability = "ADCS_CERT_ENROLL"
const ADCS_PKINIT_AUTH Capability = "ADCS_PKINIT_AUTH"

func AccessRightToCapability(edge PrivilegeEdge) Capability {
	if strings.EqualFold(edge.EdgeType, "cert") {
		return "CERT_AUTH"
	}
	if strings.EqualFold(edge.EdgeType, "adcs_cert") {
		return ADCS_PKINIT_AUTH
	}
	if strings.EqualFold(edge.EdgeType, "dcsync") {
		return "DCSync"
	}
	if strings.EqualFold(edge.EdgeType, "rbcd") {
		return "RBCD"
	}
	if strings.EqualFold(edge.EdgeType, "shadowcred") {
		return "SHADOW_CRED"
	}
	if strings.EqualFold(edge.EdgeType, "kerberoast") {
		return "KERBEROAST"
	}
	if strings.EqualFold(edge.EdgeType, "asrep") {
		return "ASREP_ROAST"
	}
	if strings.EqualFold(edge.EdgeType, "spray") {
		return "LDAP_SPRAY"
	}
	right := strings.ToUpper(edge.AccessRight)
	// Delegation rights are matched before the switch so partial-string
	// variants (e.g. "AllowedToActOnBehalfOfOtherIdentity") are recognised
	// without enumerating every spelling collectors emit.
	if strings.Contains(right, "UNCONSTRAINED") || right == "TRUSTED_FOR_DELEGATION" {
		return "UNCONSTRAINED_DELEGATION"
	}
	if strings.Contains(right, "ALLOWEDTODELEGATE") ||
		strings.Contains(right, "ALLOWEDTOACT") ||
		right == "TRUSTED_TO_AUTH_FOR_DELEGATION" {
		return "S4U_DELEGATION"
	}
	switch right {
	case "DCSYNC", "GETCHANGES", "GETCHANGESALL":
		return "DCSync"
	case "ADCS_ESC1", "ADCS_ESC13":
		return ADCS_CERT_ENROLL
	case "ADDMEMBER", "ADDSELF", "MEMBEROF":
		return "ADD_MEMBER"
	case "FORCECHANGEPASSWORD":
		return "FORCE_CHANGE_PASSWORD"
	case "WRITEDACL", "WRITEOWNER":
		return "WRITE_DACL"
	default:
		return "GenericAll"
	}
}

func (r *CapabilityRegistry) Resolve(cap Capability) (CapabilityExecutor, CapabilityResolutionStatus) {
	exec, ok := r.executors[cap]
	if !ok {
		return nil, CapabilityUnimplemented
	}
	return exec, CapabilityAvailable
}

// Capabilities returns every Capability registered with this registry as a
// slice of plain strings (the planner's expected representation). Order is
// not guaranteed; callers needing determinism should sort the result.
func (r *CapabilityRegistry) Capabilities() []string {
	out := make([]string, 0, len(r.executors))
	for cap := range r.executors {
		out = append(out, string(cap))
	}
	return out
}

// ApplyDelta applies a PostStateDelta to ADState.
// Returns true when at least one edge was added or removed (topology changed).
// Planner uses this to decide whether replanning is necessary — avoids
// wasteful recomputation when deltas only contain duplicates.
func ApplyDelta(state *ADState, delta PostStateDelta) bool {
	seen := make(map[EdgeKey]bool)
	for _, e := range state.Edges {
		seen[EdgeKeyOf(e)] = true
	}
	var added int
	for _, e := range delta.NewEdges {
		if !seen[EdgeKeyOf(e)] {
			seen[EdgeKeyOf(e)] = true
			state.Edges = append(state.Edges, e)
			added++
		}
	}

	remove := make(map[EdgeKey]bool)
	for _, k := range delta.RemovedEdges {
		remove[k] = true
	}
	filtered := make([]PrivilegeEdge, 0, len(state.Edges))
	var removed int
	for _, e := range state.Edges {
		if !remove[EdgeKeyOf(e)] {
			filtered = append(filtered, e)
		} else {
			removed++
		}
	}
	state.Edges = filtered

	changed := added > 0 || removed > 0
	if changed {
		state.Mutation.Version++
	}
	return changed
}
