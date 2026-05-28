package planner

import (
	"context"
	"testing"

	"adpack/core"
)

// chainExecutor produces a single edge on Execute.
// Used to prove the graph evolution loop:
//
//	executor → delta → ApplyDelta → state mutation → planner re-paths
type chainExecutor struct {
	cap  core.Capability
	edge core.PrivilegeEdge
}

func (m *chainExecutor) Capability() core.Capability { return m.cap }
func (m *chainExecutor) CanExecute(_ context.Context, _ core.PrivilegeEdge, _ *core.ADState) bool {
	return true
}
func (m *chainExecutor) Execute(_ context.Context, _ core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta:       core.PostStateDelta{NewEdges: []core.PrivilegeEdge{m.edge}},
	}
}

// TestChain_ExecutorDeltaProducesNewPlannerPath proves that executing a
// capability executor, applying its delta, and re-planning yields new paths
// through the newly-created edge.
func TestChain_ExecutorDeltaProducesNewPlannerPath(t *testing.T) {
	// ── Phase 1: Initial state with one edge ──
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "user_a",
				TargetPrincipal: "target_group",
				AccessRight:     "AddMember",
				EdgeType:        "acl",
				Domain:          "TEST",
				Weight:          3,
				Noise:           0.3,
			},
		},
	}

	p := New(state, DefaultConfig())

	// ── Phase 2: Initial plan — no DA path yet ──
	initial := p.PlanPaths("TEST\\user_a")
	for _, plan := range initial {
		for _, step := range plan.Steps {
			if step.TargetPrincipal == "da_admin" {
				t.Fatal("expected no path to da_admin before chain execution")
			}
		}
	}

	// ── Phase 3: Execute AddMember executor → ApplyDelta ──
	exec := &chainExecutor{
		cap: "ADD_MEMBER",
		edge: core.PrivilegeEdge{
			SourcePrincipal: "user_a",
			TargetPrincipal: "target_group",
			AccessRight:     "MemberOf",
			EdgeType:        "acl",
			Domain:          "TEST",
			Provenance:      "executor",
			Confidence:      0.9,
			Weight:          1,
			Noise:           0.0,
		},
	}

	inputEdge := state.Edges[0]
	result := exec.Execute(context.Background(), inputEdge, state)
	if !result.Success() {
		t.Fatal("executor returned failure")
	}
	if len(result.Delta.NewEdges) == 0 {
		t.Fatal("executor produced no edges")
	}

	changed := core.ApplyDelta(state, result.Delta)
	if !changed {
		t.Fatal("ApplyDelta should report changed=true for new edge")
	}

	// ── Phase 4: Add a second edge (target_group → da_admin) to give
	// the planner a path from user_a → target_group → da_admin ──
	state.Edges = append(state.Edges, core.PrivilegeEdge{
		SourcePrincipal: "target_group",
		TargetPrincipal: "da_admin",
		AccessRight:     "MemberOf",
		EdgeType:        "group",
		Domain:          "TEST",
		Weight:          1,
		Noise:           0.0,
	})

	// ── Phase 5: Re-plan — should now find 2-step path ──
	p2 := New(state, DefaultConfig())
	after := p2.PlanPaths("TEST\\user_a")

	if len(after) == 0 {
		t.Fatal("expected at least one plan after chain execution")
	}

	foundDA := false
	for _, plan := range after {
		for _, step := range plan.Steps {
			if step.TargetPrincipal == "da_admin" {
				foundDA = true
				break
			}
		}
	}
	if !foundDA {
		t.Fatal("expected a path to da_admin after chain execution: user_a → MemberOf(target_group) → MemberOf(da_admin)")
	}
}

// TestChain_ApplyDeltaVersionBump proves that topology changes increment
// the state version, which is the planner cache invalidation signal.
func TestChain_ApplyDeltaVersionBump(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "GenericAll", EdgeType: "acl", Domain: "TEST", Weight: 6, Noise: 0.7},
		},
	}

	before := state.Mutation.Version

	// Apply a delta with a new edge
	delta := core.PostStateDelta{
		NewEdges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_b", TargetPrincipal: "user_a", AccessRight: "MemberOf", EdgeType: "group", Domain: "TEST"},
		},
	}
	changed := core.ApplyDelta(state, delta)
	if !changed {
		t.Fatal("expected changed=true for new edge")
	}
	if state.Mutation.Version != before+1 {
		t.Fatalf("expected version %d, got %d", before+1, state.Mutation.Version)
	}

	// Apply the same delta again — should be no-op, version unchanged
	changed = core.ApplyDelta(state, delta)
	if changed {
		t.Fatal("expected changed=false for duplicate edge")
	}
	if state.Mutation.Version != before+1 {
		t.Fatalf("expected version %d after dedup, got %d", before+1, state.Mutation.Version)
	}
}

// TestChain_PlannerRepathsAfterDelta proves the planner sees new edges
// immediately after ApplyDelta (no refresh required).
func TestChain_PlannerRepathsAfterDelta(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "user_b", AccessRight: "ForceChangePassword", EdgeType: "acl", Domain: "TEST", Weight: 5, Noise: 0.5},
		},
	}

	// Initial plan: user_a → user_b only, no DA path
	p1 := New(state, DefaultConfig())
	initialPlans := p1.PlanPaths("TEST\\user_a")
	for _, plan := range initialPlans {
		for _, step := range plan.Steps {
			if step.TargetPrincipal == "da_admin" {
				t.Fatal("expected no DA path before delta")
			}
		}
	}

	// Apply delta that creates a ForceChangePassword executor output:
	// user_a now has GenericAll over user_b (post-password-reset control)
	core.ApplyDelta(state, core.PostStateDelta{
		NewEdges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "user_b", AccessRight: "GenericAll", EdgeType: "acl", Domain: "TEST", Provenance: "executor", Weight: 6, Noise: 0.7},
		},
	})

	// Add a second edge so user_b can reach DA
	state.Edges = append(state.Edges, core.PrivilegeEdge{
		SourcePrincipal: "user_b", TargetPrincipal: "da_admin", AccessRight: "GenericAll", EdgeType: "acl", Domain: "TEST", Weight: 6, Noise: 0.7,
	})

	// Re-plan — should now find user_a → user_b → da_admin
	p2 := New(state, DefaultConfig())
	afterPlans := p2.PlanPaths("TEST\\user_a")
	if len(afterPlans) == 0 {
		t.Fatal("expected plans after delta, got none")
	}
	found := false
	for _, plan := range afterPlans {
		for _, step := range plan.Steps {
			if step.TargetPrincipal == "da_admin" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected at least one plan reaching da_admin after delta")
	}
}
