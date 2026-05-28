# Capability Execution Contract v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Capability Execution Contract — the deterministic mapping from graph edge → executable action → graph mutation.

**Architecture:** New core types (`Capability`, `FailureMode`, `PostStateDelta`, `ExecutionResult`, `CapabilityExecutor` interface, `CapabilityRegistry`, `ApplyDelta`) in `core/capability.go`. Registry is injected from `cmd/` via the same pattern as `ExecutorFactory` and `RuntimeFactory`. This is Phase 1 — no backends yet, just the contract.

**Tech Stack:** Go, existing core types (PrivilegeEdge, ADState, resolver types)

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `core/capability.go` | Create | All core types: Capability, EdgeKey, CapabilityResolutionStatus, StateMutation, IdentityObservation, ArtifactObservation, FailureMode, PostStateDelta, ExecutionResult, CapabilityExecutor interface, CapabilityRegistry, ApplyDelta |
| `core/capability_test.go` | Create | Tests for registry, ApplyDelta, ExecutionResult.Success() |
| `core/state.go` | Modify | Add `Provenance string` to PrivilegeEdge; add `Version uint64` to ADState |
| `modules/moduleutil.go` | Modify | Add `var CapabilityRegistry *core.CapabilityRegistry` |
| `cmd/root.go` | Modify | Create registry, wire into modules |

---

### Task 1: Core types — Capability, FailureMode, PostStateDelta, ExecutionResult

**Files:**
- Create: `core/capability.go`
- Test: `core/capability_test.go`

- [ ] **Step 1: Write the failing test for ExecutionResult.Success()**

```go
package core

import (
    "testing"
)

func TestExecutionResult_Success(t *testing.T) {
    r := ExecutionResult{FailureMode: FailureSuccess}
    if !r.Success() {
        t.Fatal("expected Success() = true for FailureSuccess")
    }
}

func TestExecutionResult_NotSuccess(t *testing.T) {
    r := ExecutionResult{FailureMode: FailureRetryable}
    if r.Success() {
        t.Fatal("expected Success() = false for non-success failure mode")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./core/... -run TestExecutionResult -v -count=1`
Expected: compilation error (types not defined) or test failure

- [ ] **Step 3: Write types and Success() method**

In `core/capability.go`, add:

```go
package core

// Capability matches AccessRight on a PrivilegeEdge.
type Capability string

// EdgeKey is a deterministic, unique key for a PrivilegeEdge.
// Used for safe graph mutation (RemovedEdges) and cache invalidation.
type EdgeKey string

// EdgeKeyOf constructs the canonical key for an edge.
func EdgeKeyOf(e PrivilegeEdge) EdgeKey {
    return EdgeKey(e.Domain + "\\" + e.SourcePrincipal + "->" + e.TargetPrincipal + "#" + e.AccessRight)
}

// CapabilityResolutionStatus tells the planner why an executor wasn't found.
type CapabilityResolutionStatus int

const (
    CapabilityAvailable    CapabilityResolutionStatus = iota
    CapabilityUnimplemented
    CapabilityDisabled
)

// StateMutation tracks graph version for planner cache invalidation.
type StateMutation struct {
    Version uint64
}

// IdentityObservation and ArtifactObservation avoid leaking resolver types
// into the execution layer. Adapter code in cmd/ maps them to resolver types.
type IdentityObservation struct {
    Type string
    Data map[string]any
}

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
    RemovedEdges []EdgeKey // deterministic edge keys for removal
}

// ExecutionResult is the single output type for capability executors.
// Identities and Artifacts are observations — they go through the
// resolver pipeline, not direct graph writes.
type ExecutionResult struct {
    Delta       PostStateDelta
    FailureMode FailureMode
    Identities  []IdentityObservation
    Artifacts   []ArtifactObservation
}

func (r ExecutionResult) Success() bool { return r.FailureMode == FailureSuccess }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./core/... -run TestExecutionResult -v -count=1`
Expected: PASS

- [ ] **Step 5: Modify core/state.go — add Provenance to PrivilegeEdge, Version to ADState**

Read `core/state.go` to find the existing `PrivilegeEdge` and `ADState` struct definitions, then:

1. Add `Provenance string` to `PrivilegeEdge`
2. Add `Mutation StateMutation` to `ADState` (or add a `StateMutation Version` field)

The `StateMutation` type is already defined in `core/capability.go` (Task 1 Step 3).

```go
// In PrivilegeEdge struct (core/state.go):
    Provenance string // "bh", "relay", "resolver", "executor", "manual"

// In ADState struct (core/state.go):
    Mutation StateMutation // version tracking for planner cache invalidation
```

Run `go build ./core/... && go vet ./core/...` to verify no compilation errors from the new field (all existing edge literal initializations may need Provenance added).

- [ ] **Step 6: Commit**

```bash
git add core/capability.go core/capability_test.go core/state.go
git commit -m "feat: add capability types, edge provenance, and state versioning"
```

---

### Task 2: CapabilityExecutor interface + Registry + ApplyDelta

**Files:**
- Modify: `core/capability.go`

- [ ] **Step 1: Write the failing tests**

Add to `core/capability_test.go`:

```go
func TestCapabilityRegistry_Resolve(t *testing.T) {
    reg := NewCapabilityRegistry()
    _, status := reg.Resolve("non-existent")
    if status != CapabilityUnimplemented {
        t.Fatal("expected CapabilityUnimplemented for unregistered capability")
    }
}

type mockExecutor struct {
    cap Capability
}

func (m *mockExecutor) Capability() Capability { return m.cap }
func (m *mockExecutor) CanExecute(ctx context.Context, edge PrivilegeEdge, state *ADState) bool { return true }
func (m *mockExecutor) Execute(ctx context.Context, edge PrivilegeEdge, state *ADState) ExecutionResult {
    return ExecutionResult{FailureMode: FailureSuccess}
}

func TestCapabilityRegistry_RegisterAndResolve(t *testing.T) {
    reg := NewCapabilityRegistry()
    exec := &mockExecutor{cap: "TEST_CAP"}
    reg.Register(exec)
    resolved, status := reg.Resolve("TEST_CAP")
    if status != CapabilityAvailable {
        t.Fatal("expected CapabilityAvailable for registered capability")
    }
    if resolved.Capability() != "TEST_CAP" {
        t.Fatalf("expected TEST_CAP, got %s", resolved.Capability())
    }
}

func TestApplyDelta_NewEdges(t *testing.T) {
    state := &ADState{}
    delta := PostStateDelta{
        NewEdges: []PrivilegeEdge{
            {SourcePrincipal: "a", TargetPrincipal: "b", AccessRight: "GenericAll", Domain: "TEST"},
        },
    }
    before := state.Mutation.Version
    ApplyDelta(state, delta)
    if len(state.Edges) != 1 {
        t.Fatalf("expected 1 edge after ApplyDelta, got %d", len(state.Edges))
    }
    if state.Mutation.Version != before+1 {
        t.Fatal("expected Version to increment after ApplyDelta")
    }
}

func TestApplyDelta_RemovedEdges(t *testing.T) {
    state := &ADState{
        Edges: []PrivilegeEdge{
            {SourcePrincipal: "a", TargetPrincipal: "b", AccessRight: "GenericAll", Domain: "TEST"},
        },
    }
    // EdgeKeyOf for the above: "TEST\a->b#GenericAll"
    delta := PostStateDelta{
        RemovedEdges: []EdgeKey{EdgeKeyOf(state.Edges[0])},
    }
    ApplyDelta(state, delta)
    if len(state.Edges) != 0 {
        t.Fatalf("expected 0 edges after removal, got %d", len(state.Edges))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./core/... -run TestCapabilityRegistry|TestApplyDelta -v -count=1`
Expected: compilation errors (types/functions not defined)

- [ ] **Step 3: Implement interface, registry, ApplyDelta**

Add to `core/capability.go` (extend existing package — add `"context"` to the import block):

```go
import "context"

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
    // Dedup new edges against existing
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

    // Remove stale edges
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./core/... -run TestCapabilityRegistry|TestApplyDelta|TestExecutionResult -v -count=1`
Expected: all PASS

- [ ] **Step 5: Compile + vet full project**

```bash
go build ./core/... && go vet ./core/...
```
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add core/capability.go core/capability_test.go
git commit -m "feat: add CapabilityExecutor interface, registry, and ApplyDelta"
```

---

### Task 3: Injection wiring — modules + cmd

**Files:**
- Modify: `modules/moduleutil.go`
- Modify: `cmd/root.go`

- [ ] **Step 1: Add CapabilityRegistry variable to modules**

In `modules/moduleutil.go`, add after existing factory vars:

```go
// CapabilityRegistry is injected from cmd/. Default nil (noop).
var CapabilityRegistry *core.CapabilityRegistry
```

- [ ] **Step 2: Wire registry in cmd/root.go**

In `cmd/root.go`, after existing factory injection:

```go
modules.CapabilityRegistry = core.NewCapabilityRegistry()
```

- [ ] **Step 3: Verify compile**

Run: `go build ./... && go vet ./...`
Expected: clean

- [ ] **Step 4: Run full test suite**

Run: `go test ./... -count=1`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add modules/moduleutil.go cmd/root.go
git commit -m "feat: wire CapabilityRegistry from cmd/ to modules/"
```

---

### Task 4: Final verification

- [ ] **Step 1: gofmt**

```bash
gofmt -l .
```
Expected: no output (all clean)

- [ ] **Step 2: go vet**

```bash
go vet ./...
```
Expected: clean

- [ ] **Step 3: go build**

```bash
go build ./...
```
Expected: clean

- [ ] **Step 4: go test**

```bash
go test ./... -count=1
```
Expected: all pass

- [ ] **Step 5: go mod tidy**

```bash
go mod tidy
```
Expected: no changes
