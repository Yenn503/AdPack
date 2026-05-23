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

func TestCanExecute_ValidWithCertificateRequires(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob@test.local, Issuer=TEST-CA, Thumbprint=A1B2C3"},
	}
	if !e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = true for valid edge with cert context")
	}
}

func TestCanExecute_MissingRequires(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when Requires is empty")
	}
}

func TestCanExecute_RequiresWithoutCertPrefix(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"GenericAll", "some_other_cap"},
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when Requires has no certificate prefix")
	}
}

func TestCanExecute_EmptySource(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob"},
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when source empty")
	}
}

func TestCanExecute_EmptyTarget(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob"},
	}
	if e.CanExecute(context.Background(), edge, &core.ADState{}) {
		t.Fatal("expected CanExecute = false when target empty")
	}
}

func TestExecute_ReturnsSuccessWithAuthenticatedAsEdge(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob@test.local, Issuer=TEST-CA, Thumbprint=A1B2C3"},
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
	if ne.TargetPrincipal != "bob" {
		t.Fatalf("expected target bob, got %s", ne.TargetPrincipal)
	}
	if ne.AccessRight != "AuthenticatedAs" {
		t.Fatalf("expected AuthenticatedAs, got %s", ne.AccessRight)
	}
	if ne.EdgeType != "auth" {
		t.Fatalf("expected edge type auth, got %s", ne.EdgeType)
	}
	if ne.Provenance != "executor" {
		t.Fatalf("expected provenance executor, got %s", ne.Provenance)
	}
}

func TestExecute_ProducesIdentityObservation(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob@test.local, Issuer=TEST-CA, Thumbprint=A1B2C3"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity observation, got %d", len(result.Identities))
	}
	obs := result.Identities[0]
	if obs.Type != "certificate_auth" {
		t.Fatalf("expected type certificate_auth, got %s", obs.Type)
	}
	if obs.Data["source"] != "alice" {
		t.Fatalf("expected source alice in observation data")
	}
	if obs.Data["CN"] != "bob@test.local" {
		t.Fatalf("expected CN bob@test.local in observation data, got %v", obs.Data["CN"])
	}
	if obs.Data["Issuer"] != "TEST-CA" {
		t.Fatalf("expected Issuer TEST-CA, got %v", obs.Data["Issuer"])
	}
}

func TestExecute_ProducesArtifactObservation(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob@test.local"},
	}
	result := e.Execute(context.Background(), edge, &core.ADState{})
	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact observation, got %d", len(result.Artifacts))
	}
	obs := result.Artifacts[0]
	if obs.Type != "authenticated_session" {
		t.Fatalf("expected type authenticated_session, got %s", obs.Type)
	}
	if obs.Data["auth_method"] != "certificate" {
		t.Fatalf("expected auth_method certificate, got %v", obs.Data["auth_method"])
	}
}

func TestExecute_Deterministic(t *testing.T) {
	e := &Executor{}
	edge := core.PrivilegeEdge{
		SourcePrincipal: "alice",
		TargetPrincipal: "bob",
		Domain:          "TEST",
		Requires:        []string{"certificate:CN=bob@test.local"},
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
	if r1.Identities[0].Data["CN"] != r2.Identities[0].Data["CN"] {
		t.Fatal("expected identical identity observation across calls")
	}
}

func TestExtractCertInfo_ParsesFields(t *testing.T) {
	reqs := []string{"certificate:CN=bob@test.local, Issuer=TEST-CA, Thumbprint=A1B2C3"}
	info := extractCertInfo(reqs)
	if info["CN"] != "bob@test.local" {
		t.Fatalf("expected CN bob@test.local, got %v", info["CN"])
	}
	if info["Issuer"] != "TEST-CA" {
		t.Fatalf("expected Issuer TEST-CA, got %v", info["Issuer"])
	}
	if info["Thumbprint"] != "A1B2C3" {
		t.Fatalf("expected Thumbprint A1B2C3, got %v", info["Thumbprint"])
	}
}

func TestExtractCertInfo_EmptyReqs(t *testing.T) {
	info := extractCertInfo(nil)
	if len(info) != 0 {
		t.Fatal("expected empty info for nil Requires")
	}
}

func TestExtractCertInfo_NoCertificatePrefix(t *testing.T) {
	reqs := []string{"GenericAll", "some_cap"}
	info := extractCertInfo(reqs)
	if len(info) != 0 {
		t.Fatal("expected empty info when no certificate prefix")
	}
}
