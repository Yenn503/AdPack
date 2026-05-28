package planner

import (
	"fmt"
	"testing"

	"adpack/core"
)

func TestPlanPaths_DijkstraBasic(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "user_b", AccessRight: "GenericAll", EdgeType: "acl", Domain: "TEST", Weight: 6, Noise: 0.7},
			{SourcePrincipal: "user_b", TargetPrincipal: "da_admin", AccessRight: "ForceChangePassword", EdgeType: "acl", Domain: "TEST", Weight: 5, Noise: 0.9},
		},
	}

	p := New(state, DefaultConfig())
	plans := p.PlanPaths("TEST\\user_a")

	if len(plans) == 0 {
		t.Fatal("Expected a plan, got none")
	}
	if len(plans[0].Steps) != 2 {
		t.Errorf("Expected 2-step path, got %d steps", len(plans[0].Steps))
	}
}

func TestPlanPaths_NoiseLimit(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "DCSync", EdgeType: "acl", Domain: "TEST", Weight: 3, Noise: 1.0},
		},
	}

	cfg := DefaultConfig()
	cfg.NoiseLimit = 0.5

	p := New(state, cfg)
	plans := p.PlanPaths("TEST\\user_a")
	if len(plans) != 0 {
		t.Errorf("Expected 0 plans (noise exceeds limit), got %d", len(plans))
	}
}

func TestPlanPaths_NoEdges(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "admin", Domain: "TEST", IsDA: true},
		},
	}

	p := New(state, DefaultConfig())
	plans := p.PlanPaths("TEST\\user")
	if len(plans) != 0 {
		t.Errorf("Expected 0 plans (no edges), got %d", len(plans))
	}
}

func TestPlanPaths_MissingCaps(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "DCSync", EdgeType: "acl", Domain: "TEST", Weight: 3, Noise: 1.0, Requires: []string{"impacket-secretsdump"}},
		},
	}

	cfg := DefaultConfig()
	cfg.AvailableCaps = []string{"nxc"}

	p := New(state, cfg)
	plans := p.PlanPaths("TEST\\user_a")
	if len(plans) == 0 {
		t.Fatal("Expected a plan even with missing caps")
	}
	if len(plans[0].NeededCaps) == 0 {
		t.Error("Expected NeededCaps to report missing capabilities")
	}
}

func TestPlanPaths_MSSQLXPCmdshellSystemTarget(t *testing.T) {
	state := &core.ADState{
		Hosts: []core.Host{
			{IP: "192.168.57.22", Hostname: "CASTELBLACK", PortsOpen: "445,1433"},
		},
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "samwell.tarly",
				TargetPrincipal: "SYSTEM@192.168.57.22",
				AccessRight:     "MSSQL_XP_CMDSHELL",
				EdgeType:        "mssql_impersonation",
				Domain:          "north.sevenkingdoms.local",
				Confidence:      0.9,
				Weight:          2,
				Exploitability:  1.0,
				Noise:           0.6,
				Requires:        []string{"nxc"},
				Preconditions: []core.ExecutionPrecondition{
					{Kind: core.PrecondPortOpen, Target: "192.168.57.22", Port: 1433},
				},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.AvailableCaps = []string{"nxc"}

	plans := New(state, cfg).PlanPaths("north.sevenkingdoms.local\\samwell.tarly")
	if len(plans) == 0 {
		t.Fatal("expected MSSQL xp_cmdshell path to SYSTEM target")
	}
	if plans[0].Target != "north.sevenkingdoms.local\\SYSTEM@192.168.57.22" {
		t.Fatalf("unexpected target: %s", plans[0].Target)
	}
}

func TestPlanPaths_PortPreconditionBlocksWhenHostPortUnknown(t *testing.T) {
	state := &core.ADState{
		Hosts: []core.Host{
			{IP: "192.168.57.22", Hostname: "CASTELBLACK", PortsOpen: "445"},
		},
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "samwell.tarly",
				TargetPrincipal: "SYSTEM@192.168.57.22",
				AccessRight:     "MSSQL_XP_CMDSHELL",
				EdgeType:        "mssql_impersonation",
				Domain:          "north.sevenkingdoms.local",
				Confidence:      0.9,
				Weight:          2,
				Exploitability:  1.0,
				Noise:           0.6,
				Preconditions: []core.ExecutionPrecondition{
					{Kind: core.PrecondPortOpen, Target: "192.168.57.22", Port: 1433},
				},
			},
		},
	}

	plans := New(state, DefaultConfig()).PlanPaths("north.sevenkingdoms.local\\samwell.tarly")
	if len(plans) != 0 {
		t.Fatalf("expected no plan when 1433 is unknown, got %d", len(plans))
	}
}

func TestPlanPaths_AvoidsCycles(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "user_b", AccessRight: "GenericAll", EdgeType: "acl", Domain: "TEST", Weight: 6, Noise: 0.7},
			{SourcePrincipal: "user_b", TargetPrincipal: "user_a", AccessRight: "WriteDacl", EdgeType: "acl", Domain: "TEST", Weight: 7, Noise: 0.7},
			{SourcePrincipal: "user_b", TargetPrincipal: "da_admin", AccessRight: "ForceChangePassword", EdgeType: "acl", Domain: "TEST", Weight: 5, Noise: 0.9},
		},
	}

	p := New(state, DefaultConfig())
	plans := p.PlanPaths("TEST\\user_a")
	if len(plans) == 0 {
		t.Fatal("Expected a plan despite cycle")
	}
	if len(plans[0].Steps) != 2 {
		t.Errorf("Expected 2 steps (not cycling back), got %d", len(plans[0].Steps))
	}
}

func TestPolicy_SpeedVsStealth(t *testing.T) {
	// Two direct single-hop paths from user_a to da_admin:
	//   Noisy:  weight=4, noise=1.0 (e.g. DCSync)
	//   Quiet:  weight=6, noise=0.1 (e.g. RBCD via shadow creds)
	// Speed prefers Noisy (cost=4.5 < 6.05)
	// Stealth prefers Quiet (cost=6.5 < 9.0)
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "DCSync", EdgeType: "acl", Domain: "TEST", Weight: 4, Noise: 1.0},
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "GenericWrite", EdgeType: "acl", Domain: "TEST", Weight: 6, Noise: 0.1},
		},
	}

	// Speed policy: noise barely matters, weight dominates
	speedCfg := DefaultConfig()
	speedCfg.Policy = PolicySpeed
	speedP := New(state, speedCfg)
	speedPlans := speedP.PlanPaths("TEST\\user_a")
	if len(speedPlans) == 0 {
		t.Fatal("Expected plans under speed policy")
	}
	if speedPlans[0].Steps[0].AccessRight != "DCSync" {
		t.Errorf("Speed policy should prefer DCSync (lower weight), got %s", speedPlans[0].Steps[0].AccessRight)
	}

	// Stealth policy: noise matters significantly
	stealthCfg := DefaultConfig()
	stealthCfg.Policy = PolicyStealth
	stealthP := New(state, stealthCfg)
	stealthPlans := stealthP.PlanPaths("TEST\\user_a")
	if len(stealthPlans) == 0 {
		t.Fatal("Expected plans under stealth policy")
	}
	if stealthPlans[0].Steps[0].AccessRight != "GenericWrite" {
		t.Errorf("Stealth policy should prefer GenericWrite (lower noise), got %s", stealthPlans[0].Steps[0].AccessRight)
	}
}

func TestPolicy_MinimalTooling(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "DCSync", EdgeType: "acl", Domain: "TEST", Weight: 3, Noise: 1.0, Requires: []string{"impacket-secretsdump"}},
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "GenericAll", EdgeType: "acl", Domain: "TEST", Weight: 6, Noise: 0.7},
		},
	}

	// Minimal tooling policy: heavily penalises missing tools
	cfg := DefaultConfig()
	cfg.Policy = PolicyMinimalTooling
	cfg.AvailableCaps = []string{"nxc"}

	p := New(state, cfg)
	plans := p.PlanPaths("TEST\\user_a")

	if len(plans) == 0 {
		t.Fatal("Expected a plan under minimal_tooling policy")
	}
	if plans[0].Steps[0].AccessRight != "GenericAll" {
		t.Errorf("Minimal tooling should prefer GenericAll (no missing tools), got %s", plans[0].Steps[0].AccessRight)
	}
}

func TestPolicy_CategoricalExclusion(t *testing.T) {
	// Stealth policy should categorically exclude DCSync.
	state := &core.ADState{
		Users: []core.User{
			{Username: "da_admin", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			{SourcePrincipal: "user_a", TargetPrincipal: "da_admin", AccessRight: "DCSync", EdgeType: "acl", Domain: "TEST", Weight: 1, Noise: 1.0},
		},
	}

	cfg := DefaultConfig()
	cfg.Policy = PolicyStealth
	p := New(state, cfg)
	plans := p.PlanPaths("TEST\\user_a")
	if len(plans) != 0 {
		t.Errorf("Stealth policy should exclude DCSync, but found %d plans", len(plans))
	}
}

func TestScoreVector_Evaluation(t *testing.T) {
	capSet := map[string]bool{"nxc": true}

	// Edge with no requires: tooling gap should be 0
	e1 := core.PrivilegeEdge{Weight: 6, Noise: 0.7, Exploitability: 1.0}
	v1 := edgeToVector(e1, capSet)
	if v1.OperationalCost != 6 {
		t.Errorf("Expected OperationalCost=6, got %.1f", v1.OperationalCost)
	}
	if v1.DetectionRisk != 0.7 {
		t.Errorf("Expected DetectionRisk=0.7, got %.1f", v1.DetectionRisk)
	}
	if v1.ExecutionRisk != 0.0 {
		t.Errorf("Expected ExecutionRisk=0.0 (exploit=1.0), got %.1f", v1.ExecutionRisk)
	}
	if v1.ToolingGap != 0.0 {
		t.Errorf("Expected ToolingGap=0.0 (no requires), got %.1f", v1.ToolingGap)
	}

	// Edge with missing tool: tooling gap should be 1.0
	e2 := core.PrivilegeEdge{Weight: 3, Noise: 1.0, Exploitability: 0.95, Requires: []string{"impacket-secretsdump"}}
	v2 := edgeToVector(e2, capSet)
	if v2.ToolingGap != 1.0 {
		t.Errorf("Expected ToolingGap=1.0 (all requires missing), got %.1f", v2.ToolingGap)
	}
}

func TestProjection_NonLinear(t *testing.T) {
	// Stealth projection should apply quadratic noise penalty and cumulative
	// detection risk.
	proj := getProjection(PolicyStealth)
	v := ScoreVector{OperationalCost: 5, DetectionRisk: 0.8, ExecutionRisk: 0.1, ToolingGap: 0}
	// First step (empty path context): cost = 5 + (0.8*0.8*5) + (0*0.3) + 0 = 5 + 3.2 = 8.2
	cost, ok := proj(v, core.PrivilegeEdge{AccessRight: "GenericAll"}, emptyPathContext())
	if !ok {
		t.Fatal("Stealth should allow GenericAll")
	}
	if cost < 8.1 || cost > 8.3 {
		t.Errorf("Expected stealth cost ~8.2 for first edge, got %.2f", cost)
	}

	// Second edge with same right and cumulative noise from a previous edge:
	// Previous edge had noise=0.5, so CumulativeNoise=0.5.
	// cost = 5 + (0.8*0.8*5) + (0.5*0.5*0.3) + 3.0(repeat) = 5 + 3.2 + 0.075 + 3 = 11.275
	ctx := PathContext{StepCount: 1, CumulativeNoise: 0.5, PreviousRights: []string{"GenericAll"}}
	cost2, ok := proj(v, core.PrivilegeEdge{AccessRight: "GenericAll"}, ctx)
	if !ok {
		t.Fatal("Stealth should allow repeated GenericAll")
	}
	if cost2 < 11.0 || cost2 > 11.5 {
		t.Errorf("Expected stealth cost ~11.275 for repeat, got %.2f", cost2)
	}
}

func TestProjection_LinearSpeed(t *testing.T) {
	// Speed projection: weight + noise*0.5 + step penalty.
	// First step: 10 + 0.5*0.5 + 0*0.5 = 10.25
	proj := getProjection(PolicySpeed)
	v := ScoreVector{OperationalCost: 10, DetectionRisk: 0.5, ToolingGap: 0}
	cost, ok := proj(v, core.PrivilegeEdge{}, emptyPathContext())
	if !ok {
		t.Fatal("Speed should allow any edge")
	}
	if cost < 10.1 || cost > 10.4 {
		t.Errorf("Expected speed cost ~10.25, got %.2f", cost)
	}

	// Third step: 10 + 0.5*0.5 + 2*0.5 = 11.25
	ctx := PathContext{StepCount: 2}
	cost3, ok := proj(v, core.PrivilegeEdge{}, ctx)
	if !ok {
		t.Fatal("Speed should allow any edge")
	}
	if cost3 < 11.1 || cost3 > 11.4 {
		t.Errorf("Expected speed cost ~11.25 for step 3, got %.2f", cost3)
	}
}

func TestProjection_CumulativeNoise(t *testing.T) {
	// Verify that cumulative detection risk affects path cost under stealth.
	// Three low-noise edges (0.3 each) vs one high-noise edge (0.9):
	// Path A (3 edges): each cost = weight + (0.3*0.3*5) + cumPenalty
	//   Edge1: cum=0.0, cost = w + 0.45 + 0 = w + 0.45
	//   Edge2: cum=0.3, cost = w + 0.45 + (0.3*0.3*0.3) = w + 0.45 + 0.027 = w + 0.477
	//   Edge3: cum=0.6, cost = w + 0.45 + (0.6*0.6*0.3) = w + 0.45 + 0.108 = w + 0.558
	//   Total = 3w + 1.485
	// Path B (1 edge): cost = w + (0.9*0.9*5) + 0 = w + 4.05
	// Under stealth, 3 low-noise edges (total cost ≈ 3w+1.485) may be cheaper
	// than 1 high-noise edge (w+4.05) when w > ~1.28.

	proj := getProjection(PolicyStealth)
	// Low weight per edge so noise penalty dominates comparison
	vLow := ScoreVector{OperationalCost: 1, DetectionRisk: 0.3, ToolingGap: 0}
	vHigh := ScoreVector{OperationalCost: 1, DetectionRisk: 0.9, ToolingGap: 0}

	// Three low-noise edges
	ctx1 := PathContext{StepCount: 0}
	c1, ok := proj(vLow, core.PrivilegeEdge{AccessRight: "ReadGMSAPassword"}, ctx1)
	if !ok {
		t.Fatal("Stealth should allow low-noise edge")
	}
	ctx2 := extendPathContext(ctx1, core.PrivilegeEdge{Noise: 0.3})
	c2, ok := proj(vLow, core.PrivilegeEdge{AccessRight: "ReadGMSAPassword"}, ctx2)
	if !ok {
		t.Fatal("Stealth should allow low-noise edge")
	}
	ctx3 := extendPathContext(ctx2, core.PrivilegeEdge{Noise: 0.3})
	c3, ok := proj(vLow, core.PrivilegeEdge{AccessRight: "ReadGMSAPassword"}, ctx3)
	if !ok {
		t.Fatal("Stealth should allow low-noise edge")
	}
	totalLow := c1 + c2 + c3

	// Single high-noise edge (not DCSync — stealth categorically excludes it)
	cHigh, ok := proj(vHigh, core.PrivilegeEdge{AccessRight: "ShadowCreds"}, emptyPathContext())
	if !ok {
		t.Fatal("Stealth should allow ShadowCreds (only DCSync is categorically excluded)")
	}

	if totalLow >= cHigh {
		t.Errorf("Expected 3 low-noise edges (%.2f) < 1 high-noise edge (%.2f)", totalLow, cHigh)
	}
}

// TestResolverEdge_BridgesGraphGap validates that a resolver-emitted
// identity edge (CERT_AUTH) can create new planner paths that didn't
// exist before. This is the critical graph-semantic test: resolver edges
// must be treated as first-class traversal nodes by the planner.
func TestResolverEdge_BridgesGraphGap(t *testing.T) {
	// Baseline graph: lord.varys → GenericAll → winterfell$ but no path
	// from winterfell$ to any high-value target. Domain Admins exists
	// as a group with tywin.lannister as member, but is unreachable
	// from lord.varys.
	state := &core.ADState{
		Users: []core.User{
			{Username: "lord.varys", Domain: "sevenkingdoms.local"},
			{Username: "tywin.lannister", Domain: "sevenkingdoms.local", IsDA: true},
		},
		Groups: []core.Group{
			{Name: "domain admins", Domain: "sevenkingdoms.local"},
		},
		Edges: []core.PrivilegeEdge{
			// lord.varys can admin winterfell$
			{SourcePrincipal: "lord.varys", TargetPrincipal: "winterfell$",
				AccessRight: "GenericAll", EdgeType: "acl",
				Domain: "sevenkingdoms.local", Weight: 6, Noise: 0.7},
			// tywin is in Domain Admins
			{SourcePrincipal: "tywin.lannister", TargetPrincipal: "domain admins",
				AccessRight: "MemberOf", EdgeType: "member",
				Domain: "sevenkingdoms.local", Weight: 1, Noise: 0.1},
		},
	}

	// Baseline: no path from lord.varys to domain admins
	baseline := New(state, DefaultConfig())
	baselinePlans := baseline.PlanPaths("sevenkingdoms.local\\lord.varys")
	if len(baselinePlans) > 0 {
		t.Log("Baseline already has paths — resolver not needed for reachability")
	} else {
		t.Log("Baseline: no paths (as expected — graph is disconnected)")
	}

	// Treatment: inject a resolver-emitted CERT_AUTH edge in the format
	// produced by materializeResolverEdge. This represents an ESC8 cert
	// capture that resolves to winterfell$'s machine account.
	resolverEdge := core.PrivilegeEdge{
		SourcePrincipal: "winterfell$",
		TargetPrincipal: "domain admins",
		AccessRight:     "CERT_AUTH",
		EdgeType:        "resolved_identity",
		Domain:          "sevenkingdoms.local",
		Source:          "resolver-certipy",
		Confidence:      0.85,
		Weight:          2.0,
		Exploitability:  0.8,
		Noise:           0.3,
		Requires:        []string{"certipy"},
	}
	state.Edges = append(state.Edges, resolverEdge)

	// Re-run planner — new path should emerge
	treatment := New(state, DefaultConfig())
	treatmentPlans := treatment.PlanPaths("sevenkingdoms.local\\lord.varys")

	if len(treatmentPlans) == 0 {
		t.Fatal("Resolver edge should create a new path, but none found")
	}

	// Verify the new path uses the resolver edge
	foundResolver := false
	for _, plan := range treatmentPlans {
		for _, e := range plan.Steps {
			if e.AccessRight == "CERT_AUTH" && e.SourcePrincipal == "winterfell$" {
				foundResolver = true
				t.Logf("Resolver edge used in path: %s → %s → %s (cost=%.1f)",
					e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, plan.TotalCost)
				break
			}
		}
	}
	if !foundResolver {
		t.Error("Resolver edge exists but is not used in any path")
	}

	// Metric: the resolver should create paths that are shorter or equal
	// to what would be needed without it (or create paths where none existed)
	preCount := len(baselinePlans)
	postCount := len(treatmentPlans)
	t.Logf("Paths before: %d → after: %d (delta: +%d)", preCount, postCount, postCount-preCount)
	if postCount <= preCount {
		t.Log("Note: resolver edge didn't add new paths in this graph (may still improve other metrics)")
	}
}

// TestResolverEdge_IdentityNormalization verifies that a resolver-emitted
// edge in the correct identity format (plain name + domain, not FQDN) is
// properly found by the planner's adjacency lookup.
func TestResolverEdge_IdentityNormalization(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "user_a", Domain: "TEST", IsDA: true},
		},
		Edges: []core.PrivilegeEdge{
			// Edge from resolver-style principal format (plain name)
			{SourcePrincipal: "machine$", TargetPrincipal: "user_a",
				AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
				Domain: "TEST", Weight: 2, Noise: 0.3, Requires: []string{"certipy"}},
		},
	}

	p := New(state, DefaultConfig())

	// Start from machine$ — simulate that the resolver identity is in the creds
	plans := p.PlanPaths("TEST\\machine$")

	if len(plans) == 0 {
		t.Fatal("Resolver edge with plain name format should be traversable, but no path found")
	}
	if len(plans[0].Steps) != 1 {
		t.Fatalf("Expected 1-step path (machine$ → user_a), got %d steps", len(plans[0].Steps))
	}
	if plans[0].Steps[0].AccessRight != "CERT_AUTH" {
		t.Errorf("Expected CERT_AUTH in path, got %s", plans[0].Steps[0].AccessRight)
	}
}

// TestResolverEdge_Centrality measures how often resolver-emitted edges
// appear in optimal (lowest-cost) paths. This classifies resolver edges as
// either "structural" (used in optimal routes) or "incidental" (only expand
// reachable space). Both roles are valid, but only structural edges change
// the geometry of optimal traversal.
//
// Metrics computed:
//
//	resolver_path_ratio    = paths containing resolver edges / total paths
//	resolver_edge_coverage = unique resolver edges used / total resolver edges
//
// Design constraint: resolver edges must not be artificially preferred.
// Dijkstra and policy weighting decide naturally.
func TestResolverEdge_Centrality(t *testing.T) {
	state := &core.ADState{
		Users: []core.User{
			{Username: "user_a", Domain: "DOMAIN"},
			{Username: "user_b", Domain: "DOMAIN"},
			{Username: "user_c", Domain: "DOMAIN", IsDA: true},
		},
		Groups: []core.Group{
			{Name: "domain admins", Domain: "DOMAIN"},
			{Name: "domain controllers", Domain: "DOMAIN"},
		},
		Edges: []core.PrivilegeEdge{
			// ── BH edges ───────────────────────────────────────
			{SourcePrincipal: "user_a", TargetPrincipal: "user_b",
				AccessRight: "GenericAll", EdgeType: "acl",
				Domain: "DOMAIN", Weight: 6, Noise: 0.7, Source: "bloodhound"},
			{SourcePrincipal: "user_a", TargetPrincipal: "srv01$",
				AccessRight: "GenericAll", EdgeType: "acl",
				Domain: "DOMAIN", Weight: 6, Noise: 0.7, Source: "bloodhound"},
			{SourcePrincipal: "user_a", TargetPrincipal: "user_c",
				AccessRight: "WriteOwner", EdgeType: "acl",
				Domain: "DOMAIN", Weight: 5, Noise: 0.6, Source: "bloodhound"},
			{SourcePrincipal: "srv01$", TargetPrincipal: "user_b",
				AccessRight: "AdminTo", EdgeType: "local_admin",
				Domain: "DOMAIN", Weight: 4, Noise: 0.5, Source: "bloodhound"},
			{SourcePrincipal: "user_b", TargetPrincipal: "domain admins",
				AccessRight: "MemberOf", EdgeType: "member",
				Domain: "DOMAIN", Weight: 1, Noise: 0.1, Source: "bloodhound"},
			{SourcePrincipal: "user_c", TargetPrincipal: "domain admins",
				AccessRight: "MemberOf", EdgeType: "member",
				Domain: "DOMAIN", Weight: 1, Noise: 0.1, Source: "bloodhound"},

			// ── Resolver edges ─────────────────────────────────
			{SourcePrincipal: "srv01$", TargetPrincipal: "domain admins",
				AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
				Domain: "DOMAIN", Weight: 2, Noise: 0.3,
				Requires: []string{"certipy"}, Source: "resolver-certipy"},
			{SourcePrincipal: "user_b", TargetPrincipal: "domain controllers",
				AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
				Domain: "DOMAIN", Weight: 2, Noise: 0.3,
				Requires: []string{"certipy"}, Source: "resolver-certipy"},
			// Unused resolver edge — only reachable through srv01$,
			// but srv01$ already has a cheaper path to domain admins.
			{SourcePrincipal: "srv01$", TargetPrincipal: "enterprise admins",
				AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
				Domain: "DOMAIN", Weight: 2, Noise: 0.3,
				Requires: []string{"certipy"}, Source: "resolver-certipy"},
		},
	}

	cfg := DefaultConfig()
	cfg.MaxPaths = 20

	p := New(state, cfg)
	plans := p.PlanPaths("DOMAIN\\user_a")

	if len(plans) == 0 {
		t.Fatal("Expected at least one path from user_a")
	}

	t.Logf("=== Resolver Centrality Metrics ===")
	t.Logf("Total optimal paths: %d", len(plans))

	// Count resolver edges used
	resolverUsed := make(map[string]bool) // unique resolver edge keys used
	pathsWithResolver := 0

	for i, plan := range plans {
		hasResolver := false
		for _, e := range plan.Steps {
			if e.Source == "resolver-certipy" {
				hasResolver = true
				key := e.SourcePrincipal + "→" + e.AccessRight + "→" + e.TargetPrincipal
				resolverUsed[key] = true
			}
		}
		if hasResolver {
			pathsWithResolver++
			t.Logf("  path[%d] → %s (cost=%.1f) [uses resolver]", i, plan.Target, plan.TotalCost)
		} else {
			t.Logf("  path[%d] → %s (cost=%.1f)", i, plan.Target, plan.TotalCost)
		}
	}

	totalResolverEdges := 3
	resolverPathRatio := float64(pathsWithResolver) / float64(len(plans))
	resolverEdgeCoverage := float64(len(resolverUsed)) / float64(totalResolverEdges)

	t.Logf("=== Metrics ===")
	t.Logf("resolver_path_ratio    = %.2f (%d/%d paths contain resolver edges)",
		resolverPathRatio, pathsWithResolver, len(plans))
	t.Logf("resolver_edge_coverage = %.2f (%d/%d resolver edges used in paths)",
		resolverEdgeCoverage, len(resolverUsed), totalResolverEdges)

	// If resolver_path_ratio > 0.3, resolver edges are structural
	// (used in a significant fraction of optimal routes).
	if resolverPathRatio > 0.3 {
		t.Logf("→ Resolver edges are STRUCTURAL (appear in %.0f%% of optimal paths)",
			resolverPathRatio*100)
	} else if resolverPathRatio > 0 {
		t.Logf("→ Resolver edges are INCIDENTAL (appear in only %.0f%% of optimal paths)",
			resolverPathRatio*100)
	} else {
		t.Log("→ Resolver edges have zero centrality (not used in any optimal path)")
	}
}

// TestResolverEdge_PathDisplacement measures whether resolver edges act as
// "optional accelerators" or "topology-defining shortcuts" by comparing
// optimal path costs for each target with and without resolver edges.
//
// Metric: delta_cost_ratio = (cost_without_resolver - cost_with_resolver) /
//
//	                         cost_without_resolver
//
//	delta_cost_ratio > 0.3 → strong shortcut (resolver halves effective cost)
//	delta_cost_ratio ≈ 0   → optional accelerator (same targets, same cost)
//	inf (resolver-only)    → topology expansion (target unreachable without)
func TestResolverEdge_PathDisplacement(t *testing.T) {
	// Shared base edges (BH topology)
	bhEdges := []core.PrivilegeEdge{
		{SourcePrincipal: "user_a", TargetPrincipal: "user_b",
			AccessRight: "GenericAll", EdgeType: "acl",
			Domain: "DOMAIN", Weight: 6, Noise: 0.7, Source: "bloodhound"},
		{SourcePrincipal: "user_a", TargetPrincipal: "srv01$",
			AccessRight: "GenericAll", EdgeType: "acl",
			Domain: "DOMAIN", Weight: 6, Noise: 0.7, Source: "bloodhound"},
		{SourcePrincipal: "user_a", TargetPrincipal: "user_c",
			AccessRight: "WriteOwner", EdgeType: "acl",
			Domain: "DOMAIN", Weight: 5, Noise: 0.6, Source: "bloodhound"},
		{SourcePrincipal: "srv01$", TargetPrincipal: "user_b",
			AccessRight: "AdminTo", EdgeType: "local_admin",
			Domain: "DOMAIN", Weight: 4, Noise: 0.5, Source: "bloodhound"},
		{SourcePrincipal: "user_b", TargetPrincipal: "domain admins",
			AccessRight: "MemberOf", EdgeType: "member",
			Domain: "DOMAIN", Weight: 1, Noise: 0.1, Source: "bloodhound"},
		{SourcePrincipal: "user_c", TargetPrincipal: "domain admins",
			AccessRight: "MemberOf", EdgeType: "member",
			Domain: "DOMAIN", Weight: 1, Noise: 0.1, Source: "bloodhound"},
	}

	resolverEdges := []core.PrivilegeEdge{
		{SourcePrincipal: "srv01$", TargetPrincipal: "domain admins",
			AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
			Domain: "DOMAIN", Weight: 2, Noise: 0.3,
			Requires: []string{"certipy"}, Source: "resolver-certipy"},
		{SourcePrincipal: "user_b", TargetPrincipal: "domain controllers",
			AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
			Domain: "DOMAIN", Weight: 2, Noise: 0.3,
			Requires: []string{"certipy"}, Source: "resolver-certipy"},
		{SourcePrincipal: "srv01$", TargetPrincipal: "enterprise admins",
			AccessRight: "CERT_AUTH", EdgeType: "resolved_identity",
			Domain: "DOMAIN", Weight: 2, Noise: 0.3,
			Requires: []string{"certipy"}, Source: "resolver-certipy"},
	}

	baseState := func() *core.ADState {
		return &core.ADState{
			Users: []core.User{
				{Username: "user_a", Domain: "DOMAIN"},
				{Username: "user_b", Domain: "DOMAIN"},
				{Username: "user_c", Domain: "DOMAIN", IsDA: true},
			},
			Groups: []core.Group{
				{Name: "domain admins", Domain: "DOMAIN"},
				{Name: "domain controllers", Domain: "DOMAIN"},
			},
			Edges: append([]core.PrivilegeEdge{}, bhEdges...),
		}
	}

	// Baseline: run planner without resolver edges
	baselineState := baseState()
	baselineCfg := DefaultConfig()
	baselineCfg.MaxPaths = 20
	baselinePlans := New(baselineState, baselineCfg).PlanPaths("DOMAIN\\user_a")

	baselineCosts := make(map[string]float64)
	for _, p := range baselinePlans {
		baselineCosts[p.Target] = p.TotalCost
	}

	// Treatment: run planner WITH resolver edges
	treatmentState := baseState()
	treatmentState.Edges = append(treatmentState.Edges, resolverEdges...)
	treatmentCfg := DefaultConfig()
	treatmentCfg.MaxPaths = 20
	treatmentPlans := New(treatmentState, treatmentCfg).PlanPaths("DOMAIN\\user_a")

	treatmentCosts := make(map[string]float64)
	for _, p := range treatmentPlans {
		treatmentCosts[p.Target] = p.TotalCost
	}

	// Compute displacement per target
	allTargets := make(map[string]bool)
	for t := range baselineCosts {
		allTargets[t] = true
	}
	for t := range treatmentCosts {
		allTargets[t] = true
	}

	t.Logf("=== Path Displacement Metrics ===")
	t.Logf("%-30s %10s %10s %12s  %s", "Target", "NoResolver", "WithResolver", "DeltaRatio", "Classification")
	t.Logf("%-30s %10s %10s %12s  %s", "------", "----------", "-----------", "----------", "--------------")

	var accelCount, shortCount, expandCount int

	for target := range allTargets {
		bCost, hasB := baselineCosts[target]
		tCost, hasT := treatmentCosts[target]

		class := "BH-only"
		deltaStr := "—"

		if hasT && !hasB {
			// Resolver-only target — topology expansion
			class = "ENABLED (resolver-only)"
			expandCount++
			t.Logf("%-30s %10s %10.1f %12s  %s", target, "N/A", tCost, "∞", class)
		} else if hasB && hasT {
			deltaRatio := (bCost - tCost) / bCost
			deltaStr = fmt.Sprintf("%+.2f", deltaRatio)
			if deltaRatio > 0.3 {
				class = "strong shortcut"
				shortCount++
			} else if deltaRatio > 0.05 {
				class = "accelerator"
				accelCount++
			} else {
				class = "no change"
			}
			t.Logf("%-30s %10.1f %10.1f %12s  %s", target, bCost, tCost, deltaStr, class)
		} else {
			t.Logf("%-30s %10.1f %10s %12s  %s", target, bCost, "N/A", "—", class)
		}
	}

	t.Logf("")
	total := len(allTargets)
	t.Logf("Topology expansion: %d/%d targets (%.0f%%) — resolver-only reachable",
		expandCount, total, float64(expandCount)/float64(total)*100)
	t.Logf("Strong shortcuts:   %d/%d targets (%.0f%%) — cost reduction >30%%",
		shortCount, total, float64(shortCount)/float64(total)*100)
	t.Logf("Accelerators:       %d/%d targets (%.0f%%) — cost reduction 5-30%%",
		accelCount, total, float64(accelCount)/float64(total)*100)

	if expandCount+shortCount > 0 {
		t.Logf("→ Resolver edges are TOPOLOGY-DEFINING (expand reachability or create shortcuts)")
	} else if accelCount > 0 {
		t.Logf("→ Resolver edges are OPTIONAL ACCELERATORS (reduce cost without changing topology)")
	} else {
		t.Log("→ Resolver edges have no measurable path displacement impact")
	}
}

// computeComponents partitions graph nodes into connected components using
// bidirectional adjacency (treats Source→Target as undirected for connectivity).
// Returns component count, size of largest component, and membership map.
func computeComponents(edges []core.PrivilegeEdge) (int, int, map[string]int) {
	adj := make(map[string]map[string]bool)
	for _, e := range edges {
		src := e.Domain + "\\" + e.SourcePrincipal
		tgt := e.Domain + "\\" + e.TargetPrincipal
		if adj[src] == nil {
			adj[src] = make(map[string]bool)
		}
		if adj[tgt] == nil {
			adj[tgt] = make(map[string]bool)
		}
		adj[src][tgt] = true
		adj[tgt][src] = true
	}

	visited := make(map[string]bool)
	componentOf := make(map[string]int)
	var compID int
	largest := 0

	for node := range adj {
		if visited[node] {
			continue
		}
		// BFS
		queue := []string{node}
		visited[node] = true
		count := 0
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			componentOf[cur] = compID
			count++
			for neighbor := range adj[cur] {
				if !visited[neighbor] {
					visited[neighbor] = true
					queue = append(queue, neighbor)
				}
			}
		}
		if count > largest {
			largest = count
		}
		compID++
	}

	return compID, largest, componentOf
}

// TestResolverEdge_ComponentMergeIndex measures how resolver edges merge
// previously disconnected graph components. This is the strongest validation
// of the resolver's topological effect: merging components where no path
// existed before.
//
// Design: two disconnected components in baseline:
//
//	Component A: user_a → srv01$ (2 nodes)
//	Component B: user_b → domain admins (2 nodes, high-value target)
//
// No path from A to B in BH-only graph. Two resolver edges:
//
//	gap merge: srv01$ → CERT_AUTH → domain admins  (bridges A↔B)
//	expansion: user_b → CERT_AUTH → domain controllers (adds new node)
//
// After: single 5-node component.
func TestResolverEdge_ComponentMergeIndex(t *testing.T) {
	bhEdges := []core.PrivilegeEdge{
		// Component A
		{SourcePrincipal: "user_a", TargetPrincipal: "srv01$",
			AccessRight: "GenericAll", Domain: "DOMAIN", Source: "bloodhound"},
		// Component B
		{SourcePrincipal: "user_b", TargetPrincipal: "domain admins",
			AccessRight: "MemberOf", Domain: "DOMAIN", Source: "bloodhound"},
	}
	resolverEdges := []core.PrivilegeEdge{
		// Bridges A→B: srv01$ ∈ A, domain admins ∈ B
		{SourcePrincipal: "srv01$", TargetPrincipal: "domain admins",
			AccessRight: "CERT_AUTH", Domain: "DOMAIN", Source: "resolver-certipy"},
		// Expands merged graph: adds domain controllers as new reachable node
		{SourcePrincipal: "user_b", TargetPrincipal: "domain controllers",
			AccessRight: "CERT_AUTH", Domain: "DOMAIN", Source: "resolver-certipy"},
	}

	// Baseline: compute components without resolver edges
	baselineCount, baselineLargest, baselineComp := computeComponents(bhEdges)
	t.Logf("=== Component Merge Index ===")
	t.Logf("Baseline (BH only): %d components, largest=%d nodes", baselineCount, baselineLargest)

	// Show baseline components
	compNodes := make(map[int][]string)
	for node, cid := range baselineComp {
		compNodes[cid] = append(compNodes[cid], node)
	}
	for cid, nodes := range compNodes {
		t.Logf("  Component %d: %v", cid, nodes)
	}

	// Treatment: add resolver edges
	allEdges := append([]core.PrivilegeEdge{}, bhEdges...)
	allEdges = append(allEdges, resolverEdges...)
	treatmentCount, treatmentLargest, treatmentComp := computeComponents(allEdges)
	t.Logf("After resolver: %d components, largest=%d nodes", treatmentCount, treatmentLargest)

	// Show treatment components
	compNodesT := make(map[int][]string)
	for node, cid := range treatmentComp {
		compNodesT[cid] = append(compNodesT[cid], node)
	}
	for cid, nodes := range compNodesT {
		t.Logf("  Component %d: %v", cid, nodes)
	}

	// Metrics
	mergedCount := baselineCount - treatmentCount
	newlyReachable := treatmentLargest - baselineLargest

	t.Logf("")
	t.Logf("Components merged:             %d", mergedCount)
	t.Logf("Newly reachable nodes:          %d", newlyReachable)
	t.Logf("Component merge efficiency:     %.1f resolvers/merge", float64(len(resolverEdges))/float64(mergedCount))

	if mergedCount > 0 {
		t.Logf("→ Resolver edges are COMPONENT MERGERS (merge disconnected subgraphs)")
	} else {
		t.Logf("→ Resolver edges are INTRA-COMPONENT (no structural connectivity change)")
	}
}
