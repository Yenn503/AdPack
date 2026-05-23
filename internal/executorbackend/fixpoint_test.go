package executorbackend

import (
	"context"
	"testing"

	"adpack/core"
	"adpack/internal/executorbackend/addmember"
	"adpack/internal/executorbackend/asrep_roast"
	"adpack/internal/executorbackend/certauth"
	"adpack/internal/executorbackend/dcsync"
	"adpack/internal/executorbackend/forcechangepassword"
	"adpack/internal/executorbackend/genericall"
	"adpack/internal/executorbackend/kerberoast"
	"adpack/internal/executorbackend/ldap_spray"
	"adpack/internal/executorbackend/rbcd"
	"adpack/internal/executorbackend/shadowcred"
	"adpack/internal/executorbackend/writedacl"
	"adpack/modules"
)

func TestRunFixpoint_ConvergesOnEmptyState(t *testing.T) {
	ctx := context.Background()
	state := core.NewADState()
	reg := core.NewCapabilityRegistry()
	reg.Register(&addmember.Executor{})
	reg.Register(&forcechangepassword.Executor{})
	reg.Register(&writedacl.Executor{})
	reg.Register(&genericall.Executor{})
	reg.Register(&certauth.Executor{})
	reg.Register(&dcsync.Executor{})
	reg.Register(&rbcd.Executor{})
	reg.Register(&shadowcred.Executor{})
	reg.Register(&kerberoast.Executor{})
	reg.Register(&asrep_roast.Executor{})
	reg.Register(&ldap_spray.Executor{})

	cfg := modules.DefaultFixpointConfig()
	cfg.MaxIterations = 5

	result := modules.RunFixpoint(ctx, state, reg, cfg)
	if !result.DidConverge {
		t.Fatalf("expected convergence on empty state, got max iterations (%v)", result)
	}
	if result.EdgesAdded != 0 {
		t.Fatalf("expected 0 edges added on empty state, got %d", result.EdgesAdded)
	}
}

func TestRunFixpoint_ConvergesWithOneEdge(t *testing.T) {
	ctx := context.Background()
	state := core.NewADState()
	state.Edges = append(state.Edges, core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	})

	reg := core.NewCapabilityRegistry()
	reg.Register(&addmember.Executor{})
	reg.Register(&forcechangepassword.Executor{})
	reg.Register(&writedacl.Executor{})
	reg.Register(&genericall.Executor{})
	reg.Register(&certauth.Executor{})
	reg.Register(&dcsync.Executor{})
	reg.Register(&rbcd.Executor{})
	reg.Register(&shadowcred.Executor{})
	reg.Register(&kerberoast.Executor{})
	reg.Register(&asrep_roast.Executor{})
	reg.Register(&ldap_spray.Executor{})

	cfg := modules.DefaultFixpointConfig()

	result := modules.RunFixpoint(ctx, state, reg, cfg)
	if !result.DidConverge {
		t.Fatalf("expected convergence, got max iterations: per-iteration %v", result.PerIteration)
	}
	if result.EdgesAdded == 0 {
		t.Fatalf("expected at least 1 edge added from ForceChangePassword executor, got 0")
	}
	if result.TotalAfter <= result.TotalBefore {
		t.Fatalf("expected TotalAfter > TotalBefore (%d > %d)", result.TotalAfter, result.TotalBefore)
	}
	t.Logf("Fixpoint result: %s", modules.FixpointSummary(result))
}

func TestRunFixpoint_MultiStepChain(t *testing.T) {
	ctx := context.Background()
	state := core.NewADState()
	// ForceChangePassword → GenericAll → MemberOf (2-step chain)
	state.Edges = append(state.Edges, core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	})

	reg := core.NewCapabilityRegistry()
	reg.Register(&addmember.Executor{})
	reg.Register(&forcechangepassword.Executor{})
	reg.Register(&writedacl.Executor{})
	reg.Register(&genericall.Executor{})
	reg.Register(&certauth.Executor{})
	reg.Register(&dcsync.Executor{})
	reg.Register(&rbcd.Executor{})
	reg.Register(&shadowcred.Executor{})
	reg.Register(&kerberoast.Executor{})
	reg.Register(&asrep_roast.Executor{})
	reg.Register(&ldap_spray.Executor{})

	cfg := modules.DefaultFixpointConfig()

	result := modules.RunFixpoint(ctx, state, reg, cfg)
	if !result.DidConverge {
		t.Fatalf("expected convergence, got max iterations: per-iteration %v", result.PerIteration)
	}
	// Iteration 1: ForceChangePassword → GenericAll
	// Iteration 2: GenericAll → MemberOf
	if result.EdgesAdded < 2 {
		t.Fatalf("expected at least 2 edges in chain (ForceChangePassword→GenericAll→MemberOf), got %d (per-iter: %v)",
			result.EdgesAdded, result.PerIteration)
	}
	t.Logf("Fixpoint multi-step result: %s", modules.FixpointSummary(result))
}
