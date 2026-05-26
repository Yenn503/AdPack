package storage

import (
	"path/filepath"
	"testing"
	"time"

	"adpack/core"
)

// TestEdgePersistence_RoundTrip persists a representative PrivilegeEdge,
// reloads it via LoadEdges, and asserts every field survives unchanged.
// This is the contract test for the Capability Execution Contract's
// requirement that PrivilegeEdge be the durable, addressable unit of state.
func TestEdgePersistence_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	in := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\alice",
		TargetPrincipal: "DOMAIN\\bob",
		AccessRight:     "GenericAll",
		EdgeType:        "acl",
		Domain:          "DOMAIN",
		Source:          "daclread",
		Confidence:      0.85,
		Weight:          1.5,
		Exploitability:  0.9,
		Noise:           0.3,
		Requires:        []string{"bloodyAD", "nxc"},
		ValidationState: core.EdgeValidated,
		ObservedAt:      now,
		ObservedBy:      "privesc",
		Preconditions: []core.ExecutionPrecondition{
			{Kind: core.PrecondPortOpen, Target: "10.0.0.5", Port: 445, Description: "SMB reachable"},
			{Kind: core.PrecondAuthWorks, Target: "DOMAIN\\alice"},
		},
		Provenance:         "executor",
		LastVerifiedAt:     now.Add(-5 * time.Minute),
		VerificationMethod: "state_ground",
	}

	if err := db.SaveEdge(in); err != nil {
		t.Fatalf("SaveEdge: %v", err)
	}
	out, err := db.LoadEdges()
	if err != nil {
		t.Fatalf("LoadEdges: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(out))
	}
	got := out[0]

	assertEdgeEqual(t, in, got)

	// Idempotent upsert: writing again with mutated confidence keeps row count.
	in.Confidence = 0.42
	if err := db.SaveEdge(in); err != nil {
		t.Fatalf("re-SaveEdge: %v", err)
	}
	out, _ = db.LoadEdges()
	if len(out) != 1 {
		t.Fatalf("upsert produced duplicate row: %d edges", len(out))
	}
	if out[0].Confidence != 0.42 {
		t.Fatalf("confidence update did not apply: got %v want 0.42", out[0].Confidence)
	}
}

// TestEdgePersistence_StateRoundTrip drives a full ADState through
// SaveState/LoadState and asserts that the edge set survives transparently.
func TestEdgePersistence_StateRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	state := core.NewADState()
	state.Edges = []core.PrivilegeEdge{
		{
			SourcePrincipal: "A\\u1", TargetPrincipal: "A\\g1", AccessRight: "MemberOf",
			EdgeType: "membership", Domain: "A", Confidence: 1.0, Provenance: "bh",
		},
		{
			SourcePrincipal: "A\\u2", TargetPrincipal: "A\\dc01$", AccessRight: "UNCONSTRAINED_DELEGATION",
			EdgeType: "delegation", Domain: "A", Confidence: 0.9, Provenance: "executor",
		},
	}

	if err := db.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := db.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(loaded.Edges) != 2 {
		t.Fatalf("expected 2 edges after round-trip, got %d", len(loaded.Edges))
	}

	// SaveState must DELETE-then-INSERT so removing an edge in memory
	// removes it from the DB. Otherwise ApplyDelta removals leak forever.
	state.Edges = state.Edges[:1]
	if err := db.SaveState(state); err != nil {
		t.Fatalf("SaveState shrink: %v", err)
	}
	loaded, _ = db.LoadState()
	if len(loaded.Edges) != 1 {
		t.Fatalf("expected 1 edge after shrink, got %d", len(loaded.Edges))
	}
}

// TestClearEdges ensures the reset path empties the table.
func TestClearEdges(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "clear.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	_ = db.SaveEdge(core.PrivilegeEdge{
		SourcePrincipal: "x", TargetPrincipal: "y", AccessRight: "GenericAll",
		EdgeType: "acl", Domain: "D",
	})
	if err := db.ClearEdges(); err != nil {
		t.Fatalf("ClearEdges: %v", err)
	}
	out, _ := db.LoadEdges()
	if len(out) != 0 {
		t.Fatalf("ClearEdges left %d rows", len(out))
	}
}

func assertEdgeEqual(t *testing.T, want, got core.PrivilegeEdge) {
	t.Helper()
	if got.SourcePrincipal != want.SourcePrincipal {
		t.Errorf("SourcePrincipal: got %q want %q", got.SourcePrincipal, want.SourcePrincipal)
	}
	if got.TargetPrincipal != want.TargetPrincipal {
		t.Errorf("TargetPrincipal: got %q want %q", got.TargetPrincipal, want.TargetPrincipal)
	}
	if got.AccessRight != want.AccessRight {
		t.Errorf("AccessRight: got %q want %q", got.AccessRight, want.AccessRight)
	}
	if got.EdgeType != want.EdgeType {
		t.Errorf("EdgeType: got %q want %q", got.EdgeType, want.EdgeType)
	}
	if got.Domain != want.Domain {
		t.Errorf("Domain: got %q want %q", got.Domain, want.Domain)
	}
	if got.Source != want.Source {
		t.Errorf("Source: got %q want %q", got.Source, want.Source)
	}
	if got.Confidence != want.Confidence {
		t.Errorf("Confidence: got %v want %v", got.Confidence, want.Confidence)
	}
	if got.Weight != want.Weight {
		t.Errorf("Weight: got %v want %v", got.Weight, want.Weight)
	}
	if got.Exploitability != want.Exploitability {
		t.Errorf("Exploitability: got %v want %v", got.Exploitability, want.Exploitability)
	}
	if got.Noise != want.Noise {
		t.Errorf("Noise: got %v want %v", got.Noise, want.Noise)
	}
	if len(got.Requires) != len(want.Requires) {
		t.Errorf("Requires length: got %d want %d", len(got.Requires), len(want.Requires))
	} else {
		for i := range want.Requires {
			if got.Requires[i] != want.Requires[i] {
				t.Errorf("Requires[%d]: got %q want %q", i, got.Requires[i], want.Requires[i])
			}
		}
	}
	if got.ValidationState != want.ValidationState {
		t.Errorf("ValidationState: got %q want %q", got.ValidationState, want.ValidationState)
	}
	if !got.ObservedAt.Equal(want.ObservedAt) {
		t.Errorf("ObservedAt: got %v want %v", got.ObservedAt, want.ObservedAt)
	}
	if got.ObservedBy != want.ObservedBy {
		t.Errorf("ObservedBy: got %q want %q", got.ObservedBy, want.ObservedBy)
	}
	if len(got.Preconditions) != len(want.Preconditions) {
		t.Errorf("Preconditions length: got %d want %d", len(got.Preconditions), len(want.Preconditions))
	} else {
		for i := range want.Preconditions {
			if got.Preconditions[i] != want.Preconditions[i] {
				t.Errorf("Preconditions[%d]: got %+v want %+v", i, got.Preconditions[i], want.Preconditions[i])
			}
		}
	}
	if got.Provenance != want.Provenance {
		t.Errorf("Provenance: got %q want %q", got.Provenance, want.Provenance)
	}
	if !got.LastVerifiedAt.Equal(want.LastVerifiedAt) {
		t.Errorf("LastVerifiedAt: got %v want %v", got.LastVerifiedAt, want.LastVerifiedAt)
	}
	if got.VerificationMethod != want.VerificationMethod {
		t.Errorf("VerificationMethod: got %q want %q", got.VerificationMethod, want.VerificationMethod)
	}
}
