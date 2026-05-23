# Capability Execution Contract v1

> **Phase 1** — the missing abstraction between planner (what to do) and executor (how to do it). Defines a deterministic mapping from graph edge → executable action → graph mutation.

## Problem

The system has three validated graph producers (BH ingestion, relay capture, resolver extraction) feeding one planner, but no controlled way to *walk* planned paths. Edges describe power (`GenericAll`, `CERT_AUTH`, `RBCD_WRITE`) but nothing defines how that power becomes a state change.

Without this contract, future exploit backends will:
- Define their own success/failure semantics
- Mutate the graph inconsistently
- Leak planner assumptions into execution code

## Design Constraints

- Must match the proven resolver-layer pattern (interface-based, pluggable, runtime-attached)
- Must not couple graph semantics (edges) to execution semantics (backends)
- Must produce structured, deterministic mutations — no side effects
- Must support `CanExecute` as a pure check (no mutations)
- Must separate mutation intent (`PostStateDelta`) from application (`ApplyDelta`)

## Architecture Flow

```
Planner → planned path (sequence of edges)
   │
   ▼
For each edge (in order):
  registry.Resolve(edge.AccessRight) → CapabilityExecutor
  executor.CanExecute(ctx, edge, state) → bool (pure, no mutation)
  executor.Execute(ctx, edge, state) → ExecutionResult
   │
   ├─► ApplyDelta(state, result.Delta)
   │     (single authoritative mutation function, owned by core/state.go)
   │
   ├─► result.Identities → observation pipeline (not direct graph write)
   │     goes through resolver pipeline for re-resolution
   │
   ├─► result.Artifacts → observation pipeline → resolver reuse (optional)
   │
   └─► Replan if delta changed topology (new edges / invalidated edges)
```

## Core Types

```go
// Capability matches AccessRight on a PrivilegeEdge.
// Every edge type (GenericAll, CERT_AUTH, RBCD_WRITE, DCSync, etc.)
// maps to exactly one Capability.
type Capability string

// EdgeKey is a deterministic, unique key for a PrivilegeEdge.
// Used for safe graph mutation (RemovedEdges) and cache invalidation.
type EdgeKey string

// EdgeKeyOf constructs the canonical key for an edge.
// Format: Domain\SourcePrincipal->TargetPrincipal#AccessRight
// Guarantees deterministic matching across planner rebuilds and backends.
func EdgeKeyOf(e PrivilegeEdge) EdgeKey {
    return EdgeKey(e.Domain + "\\" + e.SourcePrincipal + "->" + e.TargetPrincipal + "#" + e.AccessRight)
}

// CapabilityResolutionStatus tells the planner why an executor wasn't found.
type CapabilityResolutionStatus int

const (
    CapabilityAvailable    CapabilityResolutionStatus = iota // executor found and ready
    CapabilityUnimplemented                                   // no executor registered for this capability
    CapabilityDisabled                                        // executor exists but explicitly disabled
)

// StateMutation tracks graph version for planner cache invalidation.
// ApplyDelta increments Version on every call that changes topology.
type StateMutation struct {
    Version uint64
}

// IdentityObservation and ArtifactObservation are opaque observation containers.
// They avoid leaking resolver-level types (resolver.Identity, resolver.ArtifactEvent)
// into the execution layer. Adapter code in cmd/ maps them to the resolver pipeline.
type IdentityObservation struct {
    Type   string
    Data   map[string]any
}

type ArtifactObservation struct {
    Type   string
    Data   map[string]any
}

// FailureMode classifies execution outcomes for planner signal.
type FailureMode string

const (
    FailureSuccess  FailureMode = "success"   // full execution completed
    FailureRetryable FailureMode = "retryable" // transient, worth retrying
    FailureDeadEnd   FailureMode = "dead_end"  // permanent, path is blocked
    FailurePartial   FailureMode = "partial"   // partial success, graph partially updated
)

// PostStateDelta separates mutation intent from application.
// No executor directly mutates state — they return a delta.
type PostStateDelta struct {
    NewEdges     []PrivilegeEdge // edges to add to the graph
    RemovedEdges []EdgeKey       // edge keys to invalidate/purge from adjacency
}

// ExecutionResult is the single output type for all capability executors.
// Observations do NOT directly mutate the graph — they are emitted to
// the observation pipeline (resolver layer). Adapter code in cmd/ maps
// IdentityObservation/ArtifactObservation to resolver Identity/ArtifactEvent.
type ExecutionResult struct {
    Delta       PostStateDelta
    FailureMode FailureMode               // single authority on outcome
    Identities  []IdentityObservation     // observations, not graph writes
    Artifacts   []ArtifactObservation     // observations, go through resolver pipeline
}

// Success returns true when execution completed fully.
// Convenience method: callers check result.Success() instead of
// comparing FailureMode directly.
func (r ExecutionResult) Success() bool { return r.FailureMode == FailureSuccess }
```

## Interface + Registry

```go
// CapabilityExecutor is the pluggable backend for one Capability.
// Implementations live in internal/executorbackend/<cap>/.
type CapabilityExecutor interface {
    // Capability returns the capability this executor handles.
    // Must match the AccessRight on PrivilegeEdge.
    Capability() Capability

    // CanExecute is PURE — no side effects, no state mutations.
    // Returns true if the executor is confident it can execute
    // this edge given the current state.
    CanExecute(ctx context.Context, edge PrivilegeEdge, state *ADState) bool

    // Execute runs the capability against the target described by edge.
    // Returns an ExecutionResult with structured mutations.
    // Must NOT mutate state directly — all mutations go through Delta.
    Execute(ctx context.Context, edge PrivilegeEdge, state *ADState) ExecutionResult
}

// CapabilityRegistry is a lookup-only registry.
// Registration happens in cmd/ via the standard injection pattern.
type CapabilityRegistry struct {
    executors map[Capability]CapabilityExecutor
}

func NewCapabilityRegistry() *CapabilityRegistry
func (r *CapabilityRegistry) Register(exec CapabilityExecutor)
func (r *CapabilityRegistry) Resolve(cap Capability) (CapabilityExecutor, CapabilityResolutionStatus)
```

## Mutation Applicator

`ApplyDelta` is the single authoritative function that translates execution results into graph mutations. It is the ONLY code that writes execution outcomes into `ADState`. This centralises state transition logic and prevents graph drift across backends.

```go
// ApplyDelta applies a PostStateDelta to ADState atomically.
// Owned by core/capability.go.
//
// Rules:
//   - NewEdges are appended to state.Edges after dedup against existing edges
//   - RemovedEdges are matched by EdgeKey and removed from state.Edges
//   - state.Version is incremented on every call (triggers planner cache invalidation)
//   - The planner's adjacency list is not rebuilt here — that happens
//     on next planner.New() call
func ApplyDelta(state *ADState, delta PostStateDelta)
```

State versioning for replan correctness:

```go
// In ADState (core/state.go):
type ADState struct {
    ...
    Mutation Version // uint64, incremented by ApplyDelta on every topology change
}
```

The planner caches adjacency and path results; these caches are invalidated when `state.Mutation.Version` differs from the version at planner creation time. This prevents stale path reuse after execution-driven graph changes.

## Integration Contract

The registry follows the same injection pattern as `ExecutorFactory` and `RuntimeFactory`:

```go
// In modules/moduleutil.go or a dedicated modules/capability.go:
var CapabilityRegistry *core.CapabilityRegistry // default nil, behaves as noop
```

```go
// In cmd/root.go:
modules.CapabilityRegistry = core.NewCapabilityRegistry()
modules.CapabilityRegistry.Register(&genericall.Executor{})
modules.CapabilityRegistry.Register(&certauth.Executor{})
```

In `modules/privesc.go`, after planning produces paths, each edge is executed through the registry:

```go
for _, step := range plannedPath.Steps {
    exec, status := CapabilityRegistry.Resolve(Capability(step.AccessRight))
    switch status {
    case core.CapabilityUnimplemented:
        continue // not implemented yet — edge is valid, planner should try other paths
    case core.CapabilityDisabled:
        continue // explicitly disabled — edge is valid but admin-blocked
    case core.CapabilityAvailable:
        if !exec.CanExecute(ctx, step, state) {
            continue // executor exists but preconditions not met
        }
    }

    result := exec.Execute(ctx, step, state)
    result := exec.Execute(ctx, step, state)

    switch result.FailureMode {
    case core.FailureSuccess:
        core.ApplyDelta(state, result.Delta)
        // emit result.Identities / result.Artifacts to observation pipeline
    case core.FailurePartial:
        core.ApplyDelta(state, result.Delta) // apply partial mutations
        // emit partial observations; edge stays in graph for retry
    case core.FailureRetryable:
        // retry up to N times before marking stale
        // no delta applied until success
    case core.FailureDeadEnd:
        // mark edge EdgeStale in state — path is permanently blocked
        // no delta applied
    }
    // replan if delta changed topology
}
```

## Failure Semantics

| FailureMode | Meaning | Planner Action |
|---|---|---|
| `retryable` | Transient failure (network, timing) | Retry edge up to N times, then mark as stale |
| `dead_end` | Permanent failure (not exploitable) | Mark edge `EdgeStale`, remove from adjacency, replan |
| `partial` | Some mutations applied, some failed | Apply partial delta, keep edge, replan with updated state |
| `success` | Full execution completed | Apply full delta, emit observations, replan |

## Edge Provenance

Every edge in the graph now carries a `Provenance` field identifying its origin:

```go
// In core/state.go, PrivilegeEdge gains:
type PrivilegeEdge struct {
    ...
    Provenance string // "bh", "relay", "resolver", "executor", "manual"
}
```

Purpose:
- Trace which layer created each edge (essential when executors produce new edges)
- Distinguish derived edges from original graph data
- Enable provenance-based planner weighting (Phase 3+)

All existing edge producers must set this field. The planner can optionally weight edges by provenance.

## CanExecute Contract

`CanExecute` must be:
- **Side-effect free with respect to ADState** — no graph mutations, no state changes
- **Externally observable probing is allowed** but must be explicitly cacheable and idempotent (e.g., port check, LDAP bind test)
- **Deterministic for same inputs and same external conditions**
- Used by planner to prune edges that can't be executed (beyond planner-level preconditions)
- **Documented exceptions**: any external probing must be declared in the executor's doc comment

## Relationship to Existing Layers

| Layer | Owns | Does NOT own |
|---|---|---|---|
| Planner | Path finding, edge selection | Execution, mutation |
| CapabilityExecutor | Execution, result production | Graph mutation, event emission |
| ApplyDelta | Graph mutation, Version incrementing | Search, planning, identity resolution |
| Resolver pipeline | Artifact → identity transformation | Execution, graph mutation |
| Observation adapter (cmd/) | IdentityObservation/ArtifactObservation → resolver pipeline bridge | Execution, mutation, planning |
| Edge provenance | Every edge producer sets Provenance field | Execution, mutation decisions |

## Phase 2 Forward Reference

Phase 2 implements the first real capability backends through this contract:
- `internal/executorbackend/genericall/` — GenericAll / WriteDacl / WriteOwner
- `internal/executorbackend/certauth/` — CERT_AUTH (ESC8 certificate authentication)
- `internal/executorbackend/dcsync/` — DCSync (DRSUAPI replication)

Each backend implements `CapabilityExecutor` and is registered in `cmd/root.go`.
