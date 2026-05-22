package core

import "context"

// Capability matches AccessRight on a PrivilegeEdge.
type Capability string

// EdgeKey is a deterministic, unique key for a PrivilegeEdge.
type EdgeKey string

// EdgeKeyOf constructs the canonical key for an edge.
func EdgeKeyOf(e PrivilegeEdge) EdgeKey {
	return EdgeKey(e.Domain + "\\" + e.SourcePrincipal + "->" + e.TargetPrincipal + "#" + e.AccessRight)
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

func (r *CapabilityRegistry) Resolve(cap Capability) (CapabilityExecutor, CapabilityResolutionStatus) {
	exec, ok := r.executors[cap]
	if !ok {
		return nil, CapabilityUnimplemented
	}
	return exec, CapabilityAvailable
}

// ApplyDelta applies a PostStateDelta to ADState.
// Increments Version on every call for planner cache invalidation.
func ApplyDelta(state *ADState, delta PostStateDelta) {
	seen := make(map[EdgeKey]bool)
	for _, e := range state.Edges {
		seen[EdgeKeyOf(e)] = true
	}
	for _, e := range delta.NewEdges {
		if !seen[EdgeKeyOf(e)] {
			seen[EdgeKeyOf(e)] = true
			state.Edges = append(state.Edges, e)
		}
	}

	remove := make(map[EdgeKey]bool)
	for _, k := range delta.RemovedEdges {
		remove[k] = true
	}
	filtered := make([]PrivilegeEdge, 0, len(state.Edges))
	for _, e := range state.Edges {
		if !remove[EdgeKeyOf(e)] {
			filtered = append(filtered, e)
		}
	}
	state.Edges = filtered

	state.Mutation.Version++
}
