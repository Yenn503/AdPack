package addmember

import (
	"context"
	"testing"

	"adpack/core"
)

func TestCapability(t *testing.T) {
	e := &Executor{}
	if e.Capability() != "ADD_MEMBER" {
		t.Fatalf("expected ADD_MEMBER, got %s", e.Capability())
	}
}

func TestCanExecute_AddMember(t *testing.T) {
	e := &Executor{}
	if !e.CanExecute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "domain admins",
		Domain:          "TEST",
		AccessRight:     "AddMember",
	}, &core.ADState{}) {
		t.Fatal("expected true for AddMember")
	}
}

func TestCanExecute_AddSelf(t *testing.T) {
	e := &Executor{}
	if !e.CanExecute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "domain admins",
		Domain:          "TEST",
		AccessRight:     "AddSelf",
	}, &core.ADState{}) {
		t.Fatal("expected true for AddSelf")
	}
}

func TestCanExecute_EmptySource(t *testing.T) {
	e := &Executor{}
	if e.CanExecute(context.Background(), core.PrivilegeEdge{
		TargetPrincipal: "domain admins",
		Domain:          "TEST",
		AccessRight:     "AddMember",
	}, &core.ADState{}) {
		t.Fatal("expected false for empty source")
	}
}

func TestExecute_AddMemberEdge(t *testing.T) {
	e := &Executor{}
	result := e.Execute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "domain admins",
		Domain:          "TEST",
		AccessRight:     "AddMember",
	}, &core.ADState{})
	if !result.Success() {
		t.Fatal("expected success")
	}
	if len(result.Delta.NewEdges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(result.Delta.NewEdges))
	}
	edge := result.Delta.NewEdges[0]
	if edge.AccessRight != "MemberOf" {
		t.Fatalf("expected MemberOf, got %s", edge.AccessRight)
	}
	if edge.SourcePrincipal != "alice" {
		t.Fatalf("expected alice, got %s", edge.SourcePrincipal)
	}
	if edge.TargetPrincipal != "domain admins" {
		t.Fatalf("expected domain admins, got %s", edge.TargetPrincipal)
	}
	if edge.Provenance != "executor" {
		t.Fatalf("expected provenance executor, got %s", edge.Provenance)
	}
}

func TestExecute_IdentityObservation(t *testing.T) {
	e := &Executor{}
	result := e.Execute(context.Background(), core.PrivilegeEdge{
		SourcePrincipal: "bob",
		TargetPrincipal: "domain admins",
		Domain:          "TEST",
		AccessRight:     "AddMember",
	}, &core.ADState{})
	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(result.Identities))
	}
	obs := result.Identities[0]
	if obs.Type != "group_member_added" {
		t.Fatalf("expected group_member_added, got %s", obs.Type)
	}
	if obs.Data["principal"] != "bob" {
		t.Fatalf("expected bob, got %v", obs.Data["principal"])
	}
}

func TestExecute_Deterministic(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "domain admins",
		Domain:          "TEST",
		AccessRight:     "AddMember",
	}
	r1 := e.Execute(context.Background(), edge, &core.ADState{})
	r2 := e.Execute(context.Background(), edge, &core.ADState{})
	if len(r1.Delta.NewEdges) != len(r2.Delta.NewEdges) {
		t.Fatal("expected deterministic output")
	}
}
