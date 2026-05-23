package bloodhound

import (
	"testing"

	"adpack/core"
	"adpack/planner"
)

func TestConvertToState_Basic(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	state := p.ConvertToState("sevenkingdoms.local")

	if len(state.Users) == 0 {
		t.Error("expected at least 1 user in converted state")
	}
	if len(state.Groups) == 0 {
		t.Error("expected at least 1 group in converted state")
	}
	if len(state.Computers) == 0 {
		t.Error("expected at least 1 computer in converted state")
	}

	t.Logf("State: %d users, %d groups, %d computers, %d edges",
		len(state.Users), len(state.Groups), len(state.Computers), len(state.Edges))
}

func TestConvertToState_EdgeQuality(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	state := p.ConvertToState("sevenkingdoms.local")

	// Verify important edges exist
	type edgeKey struct{ src, right, tgt string }
	got := make(map[edgeKey]bool)

	for _, e := range state.Edges {
		if e.Source != "bloodhound" {
			continue
		}
		got[edgeKey{e.SourcePrincipal, e.AccessRight, e.TargetPrincipal}] = true
	}

	// Group membership: Domain Admins members
	daMemberEdges := []edgeKey{
		{"administrator", "MemberOf", "domain admins"},
		{"robert.baratheon", "MemberOf", "domain admins"},
		{"cersei.lannister", "MemberOf", "domain admins"},
	}
	for _, ek := range daMemberEdges {
		if !got[ek] {
			t.Errorf("missing expected edge: %s → %s → %s", ek.src, ek.right, ek.tgt)
		}
	}

	// ACL edges from Domain Admins to KINGSLANDING$
	foundDA := false
	for ek := range got {
		if ek.right == "GenericAll" && ek.tgt == "kingslanding$" {
			foundDA = true
		}
	}
	if !foundDA {
		// This is DreadGOAD-specific — the DA may own all objects
		t.Log("Note: no DA→GenericAll→KINGSLANDING$ edge found (may vary by lab setup)")
	}

	// Count edges by type
	typeCounts := make(map[string]int)
	for _, e := range state.Edges {
		if e.Source == "bloodhound" {
			typeCounts[e.AccessRight]++
		}
	}
	t.Logf("BloodHound edge type counts:")
	for right, count := range typeCounts {
		conf := 0.0
		for _, e := range state.Edges {
			if e.Source == "bloodhound" && e.AccessRight == right {
				conf = e.Confidence
				break
			}
		}
		t.Logf("  %s: %d (conf=%.2f)", right, count, conf)
	}
}

func TestConvertToState_NoDuplicateEdges(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	state := p.ConvertToState("sevenkingdoms.local")

	seen := make(map[string]bool)
	for _, e := range state.Edges {
		key := e.SourcePrincipal + "|" + e.TargetPrincipal + "|" + e.AccessRight
		if seen[key] {
			t.Errorf("duplicate edge: %s → %s → %s", e.SourcePrincipal, e.AccessRight, e.TargetPrincipal)
		}
		seen[key] = true
	}
}

func TestConvertToState_EdgeWeights(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	state := p.ConvertToState("sevenkingdoms.local")

	for _, e := range state.Edges {
		if e.Source != "bloodhound" {
			continue
		}
		if e.Weight <= 0 {
			t.Errorf("edge %s → %s [%s] has invalid weight %.1f",
				e.SourcePrincipal, e.TargetPrincipal, e.AccessRight, e.Weight)
		}
		if e.Confidence <= 0 || e.Confidence > 1 {
			t.Errorf("edge %s → %s has invalid confidence %.2f",
				e.SourcePrincipal, e.TargetPrincipal, e.Confidence)
		}
	}
}

func TestIngestFromDirectory(t *testing.T) {
	var state core.ADState
	err := IngestFromDirectory("testdata", "sevenkingdoms.local", &state)
	if err != nil {
		t.Fatalf("IngestFromDirectory: %v", err)
	}
	if len(state.Edges) == 0 {
		t.Error("expected edges after ingestion")
	}
	if !state.BH.Ingested {
		t.Error("expected BH.Ingested to be true")
	}
	t.Logf("IngestFromDirectory: %d edges, %d users, %d groups",
		len(state.Edges), len(state.Users), len(state.Groups))
}

func TestPlannerIntegration(t *testing.T) {
	var state core.ADState
	err := IngestFromDirectory("testdata", "sevenkingdoms.local", &state)
	if err != nil {
		t.Fatalf("IngestFromDirectory: %v", err)
	}

	pl := planner.New(&state, planner.PlannerConfig{
		Policy: planner.PolicySpeed,
	})
	paths := pl.PlanPaths("sevenkingdoms.local\\lord.varys")

	if len(paths) == 0 {
		t.Fatal("no paths found from lord.varys")
	}

	t.Logf("lord.varys → %d reachable targets:", len(paths))
	limit := 3
	if len(paths) < limit {
		limit = len(paths)
	}
	for i := 0; i < limit; i++ {
		path := paths[i]
		t.Logf("  %s: cost=%.1f steps=%d weight=%.1f noise=%.1f",
			path.Target, path.TotalCost, len(path.Steps),
			path.TotalWeight, path.TotalNoise)
		for _, e := range path.Steps {
			t.Logf("    %s → %s → %s", e.SourcePrincipal, e.AccessRight, e.TargetPrincipal)
		}
	}
	if len(paths) > 3 {
		t.Logf("  ... and %d more targets", len(paths)-3)
	}
}
