package dcsync

import (
	"context"
	"testing"

	"adpack/core"
)

func TestCapability(t *testing.T) {
	e := &Executor{}
	if e.Capability() != "DCSync" {
		t.Fatalf("expected DCSync, got %s", e.Capability())
	}
}

func TestCanExecute_AccessRightDCSync(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true for DCSync access right")
	}
}

func TestCanExecute_AccessRightGetChanges(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "GetChanges",
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true for GetChanges access right")
	}
}

func TestCanExecute_RequiresGetChanges(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "GenericAll",
		Requires:        []string{"GetChangesAll"},
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true when Requires contains GetChangesAll")
	}
}

func TestCanExecute_EmptySource(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when source empty")
	}
}

func TestCanExecute_UnrelatedAccessRight(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "GenericAll",
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false for unrelated access right")
	}
}

func TestCanExecute_CaseInsensitive(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "dcsync",
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true for case-insensitive dcsync")
	}
}

func TestExecute_FullReplication_ReturnsSuccess(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if !result.Success() {
		t.Fatalf("expected Success() for full replication, got %s", result.FailureMode)
	}
	if len(result.Delta.NewEdges) != 2 {
		t.Fatalf("expected 2 edges for full replication, got %d", len(result.Delta.NewEdges))
	}
}

func TestExecute_FullReplication_EdgeContent(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	edges := result.Delta.NewEdges

	foundSIDHistory := false
	foundGoldenTicket := false
	for _, ne := range edges {
		if ne.AccessRight == "SIDHistory" {
			foundSIDHistory = true
			if ne.SourcePrincipal != "alice" {
				t.Fatal("expected SIDHistory source = alice")
			}
			if ne.TargetPrincipal != "krbtgt" {
				t.Fatal("expected SIDHistory target = krbtgt")
			}
			if ne.Provenance != "executor" {
				t.Fatal("expected SIDHistory provenance = executor")
			}
			if ne.EdgeType != "domain_trust" {
				t.Fatal("expected SIDHistory edge type = domain_trust")
			}
		}
		if ne.AccessRight == "GoldenTicket" {
			foundGoldenTicket = true
			if ne.TargetPrincipal != "DC01$" {
				t.Fatal("expected GoldenTicket target = DC01$")
			}
			if ne.EdgeType != "credential_forge" {
				t.Fatal("expected GoldenTicket edge type = credential_forge")
			}
		}
	}
	if !foundSIDHistory {
		t.Fatal("expected SIDHistory edge in full replication")
	}
	if !foundGoldenTicket {
		t.Fatal("expected GoldenTicket edge in full replication")
	}
}

func TestExecute_PartialReplication_ReturnsPartial(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "GetChanges",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if result.FailureMode != core.FailurePartial {
		t.Fatalf("expected FailurePartial for GetChanges-only, got %s", result.FailureMode)
	}
	if len(result.Delta.NewEdges) != 1 {
		t.Fatalf("expected 1 edge for partial replication, got %d", len(result.Delta.NewEdges))
	}
	if result.Delta.NewEdges[0].AccessRight != "SIDHistory" {
		t.Fatal("expected SIDHistory as the partial replication edge")
	}
}

func TestExecute_PartialFromRequires_ReturnsPartial(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "GenericAll",
		Requires:        []string{"GetChanges"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if result.FailureMode != core.FailurePartial {
		t.Fatalf("expected FailurePartial when Requires lacks GetChangesAll, got %s", result.FailureMode)
	}
}

func TestExecute_ProducesIdentityObservations(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Identities) != 2 {
		t.Fatalf("expected 2 identity observations, got %d", len(result.Identities))
	}
	types := make(map[string]bool)
	for _, obs := range result.Identities {
		types[obs.Type] = true
	}
	if !types["krbtgt_hash_inferred"] {
		t.Fatal("expected krbtgt_hash_inferred identity observation")
	}
	if !types["domain_sid"] {
		t.Fatal("expected domain_sid identity observation")
	}
}

func TestExecute_ProducesArtifactObservation(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact observation, got %d", len(result.Artifacts))
	}
	if result.Artifacts[0].Type != "replicated_secrets" {
		t.Fatalf("expected type replicated_secrets, got %s", result.Artifacts[0].Type)
	}
	if result.Artifacts[0].Data["object_count"] != "142" {
		t.Fatalf("expected object_count 142, got %v", result.Artifacts[0].Data["object_count"])
	}
}

func TestExecute_Deterministic(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "DC01$",
		Domain:          "TEST",
		AccessRight:     "DCSync",
	}
	r1 := e.Execute(context.Background(), edge, &core.ADState{})
	r2 := e.Execute(context.Background(), edge, &core.ADState{})
	if r1.FailureMode != r2.FailureMode {
		t.Fatal("expected identical FailureMode")
	}
	if len(r1.Delta.NewEdges) != len(r2.Delta.NewEdges) {
		t.Fatal("expected identical edge count")
	}
	if len(r1.Identities) != len(r2.Identities) {
		t.Fatal("expected identical identity count")
	}
}
