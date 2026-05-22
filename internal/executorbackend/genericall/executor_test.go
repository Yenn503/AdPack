package genericall

import (
	"context"
	"testing"

	"adpack/core"
)

func TestCapability(t *testing.T) {
	e := &Executor{}
	if e.Capability() != "GenericAll" {
		t.Fatalf("expected GenericAll, got %s", e.Capability())
	}
}

func TestCanExecute_ReturnsTrueWhenEdgeHasSourceAndTarget(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "Domain Admins",
		Domain:          "TEST",
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true for valid edge")
	}
}

func TestCanExecute_ReturnsFalseWhenSourceEmpty(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		TargetPrincipal: "Domain Admins",
		Domain:          "TEST",
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when source empty")
	}
}

func TestCanExecute_ReturnsFalseWhenTargetEmpty(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		Domain:          "TEST",
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when target empty")
	}
}

func TestExecute_ReturnsSuccessWithMemberOfEdge(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "Domain Admins",
		Domain:          "TEST",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if !result.Success() {
		t.Fatalf("expected Success(), got failure mode %s", result.FailureMode)
	}
	if len(result.Delta.NewEdges) != 1 {
		t.Fatalf("expected 1 new edge, got %d", len(result.Delta.NewEdges))
	}
	ne := result.Delta.NewEdges[0]
	if ne.SourcePrincipal != "alice" {
		t.Fatalf("expected source alice, got %s", ne.SourcePrincipal)
	}
	if ne.TargetPrincipal != "Domain Admins" {
		t.Fatalf("expected target Domain Admins, got %s", ne.TargetPrincipal)
	}
	if ne.AccessRight != "MemberOf" {
		t.Fatalf("expected MemberOf, got %s", ne.AccessRight)
	}
	if ne.Provenance != "executor" {
		t.Fatalf("expected provenance executor, got %s", ne.Provenance)
	}
	if ne.Confidence != 1.0 {
		t.Fatalf("expected confidence 1.0, got %f", ne.Confidence)
	}
}

func TestExecute_ProducesIdentityObservation(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "Domain Admins",
		Domain:          "TEST",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity observation, got %d", len(result.Identities))
	}
	obs := result.Identities[0]
	if obs.Type != "group_membership" {
		t.Fatalf("expected type group_membership, got %s", obs.Type)
	}
	if obs.Data["source"] != "alice" {
		t.Fatalf("expected source alice in observation data")
	}
}

func TestExecute_Deterministic(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "bob",
		TargetPrincipal: "Enterprise Admins",
		Domain:          "TEST",
	}
	r1 := e.Execute(context.Background(), edge, &core.ADState{})
	r2 := e.Execute(context.Background(), edge, &core.ADState{})
	if r1.FailureMode != r2.FailureMode {
		t.Fatal("expected identical FailureMode across calls")
	}
	if len(r1.Delta.NewEdges) != len(r2.Delta.NewEdges) {
		t.Fatal("expected identical edge count across calls")
	}
	if r1.Delta.NewEdges[0].AccessRight != r2.Delta.NewEdges[0].AccessRight {
		t.Fatal("expected identical edge content across calls")
	}
}
