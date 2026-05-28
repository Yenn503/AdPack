package unconstrained_delegation

import (
	"context"
	"testing"

	"adpack/core"
)

func TestExecutor_Capability(t *testing.T) {
	t.Parallel()
	if got := (&Executor{}).Capability(); got != "UNCONSTRAINED_DELEGATION" {
		t.Fatalf("Capability(): got %q want UNCONSTRAINED_DELEGATION", got)
	}
}

func TestExecutor_CanExecute(t *testing.T) {
	t.Parallel()
	ex := &Executor{}
	ctx := context.Background()
	cases := []struct {
		name string
		edge core.PrivilegeEdge
		want bool
	}{
		{
			name: "canonical UNCONSTRAINED_DELEGATION",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "DOM\\srv01$", TargetPrincipal: "DOM\\Domain Admins",
				AccessRight: "UNCONSTRAINED_DELEGATION", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "TRUSTED_FOR_DELEGATION raw flag",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "DOM\\srv01$", TargetPrincipal: "DOM\\dc01$",
				AccessRight: "TRUSTED_FOR_DELEGATION", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "case-insensitive Unconstrained_Delegation",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "Unconstrained_Delegation", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "GenericAll should NOT match",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "GenericAll", Domain: "DOM",
			},
			want: false,
		},
		{
			name: "constrained delegation should NOT match",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "ALLOWEDTODELEGATE", Domain: "DOM",
			},
			want: false,
		},
		{
			name: "missing domain rejected",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "UNCONSTRAINED_DELEGATION",
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ex.CanExecute(ctx, tc.edge, nil); got != tc.want {
				t.Fatalf("CanExecute: got %v want %v", got, tc.want)
			}
		})
	}
}

func TestExecutor_Execute_DerivedEdges(t *testing.T) {
	t.Parallel()
	ex := &Executor{}
	in := core.PrivilegeEdge{
		SourcePrincipal: "SEVENKINGDOMS\\KINGSLANDING$",
		TargetPrincipal: "SEVENKINGDOMS\\Domain Admins",
		AccessRight:     "UNCONSTRAINED_DELEGATION",
		EdgeType:        "delegation",
		Domain:          "sevenkingdoms.local",
		Confidence:      0.9,
	}

	res := ex.Execute(context.Background(), in, nil)
	if !res.Success() {
		t.Fatalf("expected success, got %s", res.FailureMode)
	}
	if len(res.Delta.NewEdges) != 2 {
		t.Fatalf("expected 2 derived edges (DCSync + GoldenTicket), got %d", len(res.Delta.NewEdges))
	}

	var sawDCSync, sawGolden bool
	for _, e := range res.Delta.NewEdges {
		if e.Provenance != "executor" {
			t.Errorf("derived edge missing Provenance=executor: %+v", e)
		}
		if e.Domain != in.Domain {
			t.Errorf("derived edge domain mismatch: got %q want %q", e.Domain, in.Domain)
		}
		if e.SourcePrincipal != in.SourcePrincipal {
			t.Errorf("derived edge should be attributed to source: got %q want %q", e.SourcePrincipal, in.SourcePrincipal)
		}
		switch e.AccessRight {
		case "DCSync":
			sawDCSync = true
			if e.TargetPrincipal != in.TargetPrincipal {
				t.Errorf("DCSync edge target should be the DC: got %q", e.TargetPrincipal)
			}
		case "GoldenTicket":
			sawGolden = true
			if e.TargetPrincipal != "krbtgt" {
				t.Errorf("GoldenTicket edge target should be krbtgt: got %q", e.TargetPrincipal)
			}
		default:
			t.Errorf("unexpected derived AccessRight: %q", e.AccessRight)
		}
	}
	if !sawDCSync || !sawGolden {
		t.Errorf("missing required derived edge — DCSync=%v Golden=%v", sawDCSync, sawGolden)
	}

	if len(res.Identities) == 0 {
		t.Error("expected at least one identity observation")
	}
	if len(res.Artifacts) == 0 {
		t.Error("expected at least one artifact observation")
	}
}
