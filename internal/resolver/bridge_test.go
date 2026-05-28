package resolver

import (
	"testing"

	"adpack/core"
)

func TestBuildDeltaFromResolved_Nil(t *testing.T) {
	d := BuildDeltaFromResolved(nil, core.ServiceEvent{})
	if d != nil {
		t.Fatal("expected nil delta for nil resolved")
	}
}

func TestBuildDeltaFromResolved_EmptyIdentity(t *testing.T) {
	d := BuildDeltaFromResolved(&ResolvedArtifact{
		Identity:   Identity{Name: "", Domain: ""},
		Capability: "CERT_AUTH",
	}, core.ServiceEvent{})
	if d != nil {
		t.Fatal("expected nil delta for empty identity")
	}
}

func TestBuildDeltaFromResolved_CertAuth_HasSession(t *testing.T) {
	d := BuildDeltaFromResolved(&ResolvedArtifact{
		Identity:   Identity{Name: "alice", Domain: "TEST"},
		Capability: "CERT_AUTH",
		Confidence: 0.85,
		Source:     "certipy",
	}, core.ServiceEvent{})
	if d == nil {
		t.Fatal("expected non-nil delta")
	}
	if len(d.NewEdges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(d.NewEdges))
	}
	e := d.NewEdges[0]
	if e.SourcePrincipal != "alice" {
		t.Fatalf("expected source alice, got %s", e.SourcePrincipal)
	}
	if e.TargetPrincipal != "TEST\\Domain Controllers" {
		t.Fatalf("expected target TEST\\Domain Controllers, got %s", e.TargetPrincipal)
	}
	if e.AccessRight != "HasSession" {
		t.Fatalf("expected HasSession, got %s", e.AccessRight)
	}
	if e.EdgeType != "cert" {
		t.Fatalf("expected edge type cert, got %s", e.EdgeType)
	}
	if e.Provenance != "resolver:cert_auth" {
		t.Fatalf("expected provenance resolver:cert_auth, got %s", e.Provenance)
	}
	if e.Confidence != 0.85 {
		t.Fatalf("expected confidence 0.85, got %f", e.Confidence)
	}
}

func TestBuildDeltaFromResolved_CertAuth_WithTarget(t *testing.T) {
	d := BuildDeltaFromResolved(&ResolvedArtifact{
		Identity:   Identity{Name: "bob", Domain: "TEST"},
		Capability: "CERT_AUTH",
		Confidence: 0.9,
	}, core.ServiceEvent{
		Data: map[string]any{"target_principal": "DC01$"},
	})
	if d == nil {
		t.Fatal("expected non-nil delta")
	}
	e := d.NewEdges[0]
	if e.TargetPrincipal != "DC01$" {
		t.Fatalf("expected target DC01$, got %s", e.TargetPrincipal)
	}
}

func TestBuildDeltaFromResolved_GenericAll(t *testing.T) {
	d := BuildDeltaFromResolved(&ResolvedArtifact{
		Identity:   Identity{Name: "mallory", Domain: "TEST"},
		Capability: "GENERIC_ALL",
		Confidence: 0.75,
	}, core.ServiceEvent{})
	if d == nil {
		t.Fatal("expected non-nil delta")
	}
	e := d.NewEdges[0]
	if e.SourcePrincipal != "mallory" {
		t.Fatalf("expected source mallory, got %s", e.SourcePrincipal)
	}
	if e.AccessRight != "GenericAll" {
		t.Fatalf("expected GenericAll, got %s", e.AccessRight)
	}
	if e.Provenance != "resolver:generic_all" {
		t.Fatalf("expected provenance resolver:generic_all, got %s", e.Provenance)
	}
}

func TestBuildDeltaFromResolved_UnhandledCapability(t *testing.T) {
	d := BuildDeltaFromResolved(&ResolvedArtifact{
		Identity:   Identity{Name: "eve", Domain: "TEST"},
		Capability: "RBCD_WRITE",
		Confidence: 0.5,
	}, core.ServiceEvent{})
	if d != nil {
		t.Fatal("expected nil for unhandled capability")
	}
}

func TestBuildDeltaFromResolved_ApplyDeltaRoundTrip(t *testing.T) {
	state := &core.ADState{}
	d := BuildDeltaFromResolved(&ResolvedArtifact{
		Identity:   Identity{Name: "alice", Domain: "TEST"},
		Capability: "CERT_AUTH",
		Confidence: 0.85,
	}, core.ServiceEvent{})
	if d == nil {
		t.Fatal("expected non-nil delta")
	}
	changed := core.ApplyDelta(state, *d)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if len(state.Edges) != 1 {
		t.Fatalf("expected 1 edge in state, got %d", len(state.Edges))
	}
	if state.Edges[0].Provenance != "resolver:cert_auth" {
		t.Fatalf("expected provenance resolver:cert_auth, got %s", state.Edges[0].Provenance)
	}

	// Apply same delta again — should be deduped (no-op)
	changed = core.ApplyDelta(state, *d)
	if changed {
		t.Fatal("expected changed=false on dedup")
	}
	if len(state.Edges) != 1 {
		t.Fatal("expected still 1 edge after dedup")
	}
}

func TestExtractTarget_FromTargetPrincipal(t *testing.T) {
	target := extractTarget(core.ServiceEvent{
		Data: map[string]any{"target_principal": "DC01$"},
	})
	if target != "DC01$" {
		t.Fatalf("expected DC01$, got %s", target)
	}
}

func TestExtractTarget_FromTarget(t *testing.T) {
	target := extractTarget(core.ServiceEvent{
		Data: map[string]any{"target": "dc01.test.local"},
	})
	if target != "dc01.test.local" {
		t.Fatalf("expected dc01.test.local, got %s", target)
	}
}

func TestExtractTarget_Empty(t *testing.T) {
	target := extractTarget(core.ServiceEvent{})
	if target != "" {
		t.Fatalf("expected empty, got %s", target)
	}
}
