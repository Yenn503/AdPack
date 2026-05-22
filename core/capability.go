package core

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
