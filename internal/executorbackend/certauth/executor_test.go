package certauth

import (
	"context"
	"testing"

	"adpack/core"
)

func TestCapability(t *testing.T) {
	e := &Executor{}
	if e.Capability() != "CERT_AUTH" {
		t.Fatalf("expected CERT_AUTH, got %s", e.Capability())
	}
}

func TestCanExecute_ValidWithCATemplate(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice@test.local, CA=corp-CA, Template=User"},
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true for edge with CA and Template")
	}
}

func TestCanExecute_ValidWithCAOnly(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CA=corp-CA"},
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true when CA is present")
	}
}

func TestCanExecute_InvalidMissingCertContext(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when no cert context")
	}
}

func TestCanExecute_InvalidNoCAOrTemplate(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice"},
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when no CA or Template")
	}
}

func TestCanExecute_InvalidMissingSource(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CA=corp-CA"},
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when source empty")
	}
}

func TestExecute_ReturnsSuccessWithHasSessionEdge(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "dc01$",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice@test.local, CA=corp-CA, Template=User, UPN=alice@test.local"},
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
	if ne.TargetPrincipal != "dc01$" {
		t.Fatalf("expected target dc01$, got %s", ne.TargetPrincipal)
	}
	if ne.AccessRight != "HasSession" {
		t.Fatalf("expected HasSession, got %s", ne.AccessRight)
	}
	if ne.EdgeType != "cert" {
		t.Fatalf("expected edge type cert, got %s", ne.EdgeType)
	}
	if ne.Provenance != "executor" {
		t.Fatalf("expected provenance executor, got %s", ne.Provenance)
	}
}

func TestExecute_ProducesIdentityObservation(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice@test.local, CA=corp-CA, Template=User, UPN=alice@test.local"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity observation, got %d", len(result.Identities))
	}
	obs := result.Identities[0]
	if obs.Type != "certificate_auth" {
		t.Fatalf("expected type certificate_auth, got %s", obs.Type)
	}
	if obs.Data["principal"] != "alice" {
		t.Fatalf("expected principal alice, got %v", obs.Data["principal"])
	}
	if obs.Data["template"] != "User" {
		t.Fatalf("expected template User, got %v", obs.Data["template"])
	}
	if obs.Data["ca"] != "corp-CA" {
		t.Fatalf("expected ca corp-CA, got %v", obs.Data["ca"])
	}
	if obs.Data["upn"] != "alice@test.local" {
		t.Fatalf("expected upn alice@test.local, got %v", obs.Data["upn"])
	}
	if obs.Data["auth_type"] != "pkinit" {
		t.Fatalf("expected auth_type pkinit, got %v", obs.Data["auth_type"])
	}
}

func TestExecute_NoArtifactObservation(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CA=corp-CA, Template=User"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Artifacts) != 0 {
		t.Fatalf("expected 0 artifact observations, got %d", len(result.Artifacts))
	}
}

func TestExecute_DefaultsUPNWhenMissing(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice, CA=corp-CA, Template=User"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	obs := result.Identities[0]
	if obs.Data["upn"] != "alice@TEST" {
		t.Fatalf("expected upn alice@TEST, got %v", obs.Data["upn"])
	}
}

func TestExecute_DefaultsAuthType(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice, CA=corp-CA, Template=User"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	obs := result.Identities[0]
	if obs.Data["auth_type"] != "pkinit" {
		t.Fatalf("expected auth_type pkinit, got %v", obs.Data["auth_type"])
	}
}

func TestExecute_Deterministic(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "corp-CA",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=alice, CA=corp-CA, Template=User"},
	}
	r1 := e.Execute(context.Background(), edge, &core.ADState{})
	r2 := e.Execute(context.Background(), edge, &core.ADState{})
	if r1.FailureMode != r2.FailureMode {
		t.Fatal("expected identical FailureMode")
	}
	if r1.Delta.NewEdges[0].AccessRight != r2.Delta.NewEdges[0].AccessRight {
		t.Fatal("expected identical edge")
	}
	if r1.Identities[0].Data["auth_type"] != r2.Identities[0].Data["auth_type"] {
		t.Fatal("expected identical identity observation")
	}
}

func TestExtractCertInfo_ParsesFields(t *testing.T) {
	reqs := []string{"certificate:CN=alice, CA=corp-CA, Template=User, UPN=alice@test.local"}
	info := extractCertInfo(reqs)
	if info["CN"] != "alice" {
		t.Fatalf("expected CN alice, got %v", info["CN"])
	}
	if info["CA"] != "corp-CA" {
		t.Fatalf("expected CA corp-CA, got %v", info["CA"])
	}
	if info["Template"] != "User" {
		t.Fatalf("expected Template User, got %v", info["Template"])
	}
	if info["UPN"] != "alice@test.local" {
		t.Fatalf("expected UPN alice@test.local, got %v", info["UPN"])
	}
}

func TestExtractCertInfo_NilReqs(t *testing.T) {
	info := extractCertInfo(nil)
	if info != nil {
		t.Fatal("expected nil for nil Requires")
	}
}

func TestExtractCertInfo_NoCertificatePrefix(t *testing.T) {
	reqs := []string{"GenericAll"}
	info := extractCertInfo(reqs)
	if info != nil {
		t.Fatal("expected nil when no certificate prefix")
	}
}
