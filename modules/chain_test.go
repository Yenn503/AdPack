package modules

import (
	"testing"

	"adpack/core"
)

func TestChainComposer_emptyState(t *testing.T) {
	state := &core.ADState{}
	hints := ChainComposer(state)
	if len(hints) != 0 {
		t.Fatalf("expected 0 hints for empty state, got %d", len(hints))
	}
}

func TestChainComposer_kerberoastDetected(t *testing.T) {
	state := &core.ADState{
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "alice",
				TargetPrincipal: "sql_svc",
				AccessRight:     "ServicePrincipalName",
				EdgeType:        "kerberoast",
				Domain:          "TEST",
			},
		},
	}
	hints := ChainComposer(state)
	if len(hints) == 0 {
		t.Fatal("expected at least one hint for kerberoast edge")
	}
	found := false
	for _, h := range hints {
		if h.ToCapability == "KERBEROAST" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected KERBEROAST hint for SPN edge")
	}
}

func TestChainComposer_rbcdPlusDcsync(t *testing.T) {
	state := &core.ADState{
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "alice",
				TargetPrincipal: "DC01$",
				AccessRight:     "AllowedToActOnBehalfOfOtherIdentity",
				EdgeType:        "rbcd",
				Domain:          "TEST",
			},
			{
				SourcePrincipal: "DC01$",
				TargetPrincipal: "DC01$",
				AccessRight:     "DCSync",
				EdgeType:        "dcsync",
				Domain:          "TEST",
			},
		},
	}
	hints := ChainComposer(state)
	found := false
	for _, h := range hints {
		if h.ToCapability == "DCSYNC" && h.StepNumber == 2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected DCSYNC step-2 hint for RBCD + DCSync chain")
	}
}

func TestChainComposer_shadowCredChain(t *testing.T) {
	state := &core.ADState{
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				AccessRight:     "KeyCredentialLink",
				EdgeType:        "shadowcred",
				Domain:          "TEST",
			},
			{
				SourcePrincipal: "alice",
				TargetPrincipal: "DC01$",
				AccessRight:     "GenericAll",
				EdgeType:        "acl",
				Domain:          "TEST",
			},
		},
	}
	hints := ChainComposer(state)
	foundStep1 := false
	for _, h := range hints {
		if h.ToCapability == "DCSYNC" {
			foundStep1 = true
			break
		}
	}
	if !foundStep1 {
		t.Fatal("expected DCSYNC hint in shadow cred chain with edge to DC")
	}
}

func TestChainComposer_genericAllOnDC(t *testing.T) {
	state := &core.ADState{
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "alice",
				TargetPrincipal: "DC01$",
				AccessRight:     "GenericAll",
				EdgeType:        "acl",
				Domain:          "TEST",
			},
		},
	}
	hints := ChainComposer(state)
	found := false
	for _, h := range hints {
		if h.ToCapability == "DCSYNC" && h.StepNumber == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected DCSYNC hint for GenericAll on DC")
	}
}
