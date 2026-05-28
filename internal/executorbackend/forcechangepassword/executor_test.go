package forcechangepassword

import (
	"context"
	"testing"

	"adpack/core"
)

func TestCapability(t *testing.T) {
	e := &Executor{}
	if e.Capability() != "FORCE_CHANGE_PASSWORD" {
		t.Fatalf("expected FORCE_CHANGE_PASSWORD, got %s", e.Capability())
	}
}

func TestCanExecute_Valid(t *testing.T) {
	e := &Executor{}
	if !e.CanExecute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	}, &core.ADState{}) {
		t.Fatal("expected true for ForceChangePassword")
	}
}

func TestCanExecute_WrongAccessRight(t *testing.T) {
	e := &Executor{}
	if e.CanExecute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "GenericAll",
	}, &core.ADState{}) {
		t.Fatal("expected false for GenericAll")
	}
}

func TestCanExecute_EmptySource(t *testing.T) {
	e := &Executor{}
	if e.CanExecute(context.Background(), core.PrivilegeEdge{
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	}, &core.ADState{}) {
		t.Fatal("expected false for empty source")
	}
}

func TestExecute_GenericAllEdge(t *testing.T) {
	e := &Executor{}
	result := e.Execute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	}, &core.ADState{})
	if !result.Success() {
		t.Fatal("expected success")
	}
	if len(result.Delta.NewEdges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(result.Delta.NewEdges))
	}
	edge := result.Delta.NewEdges[0]
	if edge.AccessRight != "GenericAll" {
		t.Fatalf("expected GenericAll, got %s", edge.AccessRight)
	}
	if edge.SourcePrincipal != "alice" {
		t.Fatalf("expected alice, got %s", edge.SourcePrincipal)
	}
	if edge.Provenance != "executor" {
		t.Fatalf("expected provenance executor, got %s", edge.Provenance)
	}
}

func TestExecute_IdentityObservation(t *testing.T) {
	e := &Executor{}
	result := e.Execute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "mallory",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	}, &core.ADState{})
	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(result.Identities))
	}
	obs := result.Identities[0]
	if obs.Type != "password_reset" {
		t.Fatalf("expected password_reset, got %s", obs.Type)
	}
}

func TestExecute_Deterministic(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		AccessRight:     "ForceChangePassword",
	}
	r1 := e.Execute(context.Background(), edge, &core.ADState{})
	r2 := e.Execute(context.Background(), edge, &core.ADState{})
	if len(r1.Delta.NewEdges) != len(r2.Delta.NewEdges) {
		t.Fatal("expected deterministic output")
	}
}
