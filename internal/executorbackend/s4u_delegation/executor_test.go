package s4u_delegation

import (
	"context"
	"testing"

	"adpack/core"
)

func TestExecutor_Capability(t *testing.T) {
	t.Parallel()
	if got := (&Executor{}).Capability(); got != "S4U_DELEGATION" {
		t.Fatalf("Capability(): got %q want S4U_DELEGATION", got)
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
			name: "ALLOWEDTODELEGATE constrained",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "DOM\\svc1$", TargetPrincipal: "DOM\\dc01$",
				AccessRight: "AllowedToDelegateTo", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "ALLOWEDTOACT RBCD exploit",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "DOM\\svc1$", TargetPrincipal: "DOM\\dc01$",
				AccessRight: "AllowedToActOnBehalfOfOtherIdentity", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "TRUSTED_TO_AUTH_FOR_DELEGATION",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "TRUSTED_TO_AUTH_FOR_DELEGATION", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "EdgeType=rbcd_exploit",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				EdgeType: "rbcd_exploit", Domain: "DOM",
			},
			want: true,
		},
		{
			name: "Unconstrained delegation should NOT match",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "UNCONSTRAINED_DELEGATION", Domain: "DOM",
			},
			want: false,
		},
		{
			name: "GenericAll should NOT match",
			edge: core.PrivilegeEdge{
				SourcePrincipal: "a", TargetPrincipal: "b",
				AccessRight: "GenericAll", Domain: "DOM",
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

func TestExecutor_Execute_ConstrainedVariant(t *testing.T) {
	t.Parallel()
	ex := &Executor{}
	in := core.PrivilegeEdge{
		SourcePrincipal: "DOM\\svc-mssql$",
		TargetPrincipal: "DOM\\sql01$",
		AccessRight:     "AllowedToDelegateTo",
		EdgeType:        "delegation",
		Domain:          "DOM",
	}

	res := ex.Execute(context.Background(), in, nil)
	if !res.Success() {
		t.Fatalf("expected success, got %s", res.FailureMode)
	}
	if len(res.Delta.NewEdges) != 2 {
		t.Fatalf("expected 2 derived edges, got %d", len(res.Delta.NewEdges))
	}
	for _, e := range res.Delta.NewEdges {
		if e.EdgeType == "constrained_delegation" {
			return
		}
	}
	t.Error("constrained variant must produce an edge with EdgeType=constrained_delegation")
}

func TestExecutor_Execute_RBCDVariant(t *testing.T) {
	t.Parallel()
	ex := &Executor{}
	in := core.PrivilegeEdge{
		SourcePrincipal: "DOM\\attacker$",
		TargetPrincipal: "DOM\\victim$",
		AccessRight:     "AllowedToActOnBehalfOfOtherIdentity",
		Domain:          "DOM",
	}

	res := ex.Execute(context.Background(), in, nil)
	if !res.Success() {
		t.Fatalf("expected success, got %s", res.FailureMode)
	}

	var sawRBCD bool
	for _, e := range res.Delta.NewEdges {
		if e.Provenance != "executor" {
			t.Errorf("derived edge missing Provenance=executor: %+v", e)
		}
		if e.EdgeType == "rbcd_exploit" {
			sawRBCD = true
		}
	}
	if !sawRBCD {
		t.Error("RBCD variant must produce an edge with EdgeType=rbcd_exploit")
	}
}
