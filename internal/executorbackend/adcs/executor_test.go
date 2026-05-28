package adcs

import (
	"context"
	"testing"
	"time"

	"adpack/core"
)

func TestCertEnrollCanExecute(t *testing.T) {
	e := &CertEnrollExecutor{}
	ctx := context.Background()
	state := &core.ADState{}

	// Empty edge should always be rejected
	empty := core.PrivilegeEdge{}
	if e.CanExecute(ctx, empty, state) {
		t.Error("empty edge should not be executable")
	}

	// Stale edge should be rejected regardless of certipy
	stale := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\user",
		TargetPrincipal: "CA-SERVER",
		AccessRight:     "ESC1",
		Domain:          "DOMAIN",
		ObservedAt:      time.Now().Add(-10 * time.Minute),
	}
	if e.CanExecute(ctx, stale, state) {
		t.Error("stale edge should not be executable")
	}
}

func TestPKINITAuthCanExecute(t *testing.T) {
	e := &PKINITAuthExecutor{}
	ctx := context.Background()
	state := &core.ADState{}

	// Missing pfx should be rejected
	noPfx := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\user",
		TargetPrincipal: "DOMAIN\\DA",
		AccessRight:     "HasCertificate",
		EdgeType:        "adcs_cert",
		Domain:          "DOMAIN",
		ObservedAt:      time.Now(),
	}
	if e.CanExecute(ctx, noPfx, state) {
		t.Error("edge without pfx should not be executable")
	}

	// Wrong access right should be rejected
	wrongAr := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\user",
		TargetPrincipal: "DOMAIN\\DA",
		AccessRight:     "GenericAll",
		Domain:          "DOMAIN",
		ObservedAt:      time.Now(),
		Requires:        []string{"has_pfx"},
	}
	if e.CanExecute(ctx, wrongAr, state) {
		t.Error("edge with wrong access right should not be executable")
	}

	// Empty edge should be rejected
	empty := core.PrivilegeEdge{}
	if e.CanExecute(ctx, empty, state) {
		t.Error("empty edge should not be executable")
	}

	// Valid edge: only assert if certipy is available
	valid := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\user",
		TargetPrincipal: "DOMAIN\\DA",
		AccessRight:     "HasCertificate",
		EdgeType:        "adcs_cert",
		Domain:          "DOMAIN",
		ObservedAt:      time.Now(),
		Requires:        []string{"has_pfx"},
	}
	if certipyAvailable() && !e.CanExecute(ctx, valid, state) {
		t.Error("valid edge should be executable when certipy is available")
	}
}

func TestEdgeStaleness(t *testing.T) {
	fresh := core.PrivilegeEdge{ObservedAt: time.Now()}
	if isEdgeStale(fresh) {
		t.Error("fresh edge should not be stale")
	}

	stale := core.PrivilegeEdge{ObservedAt: time.Now().Add(-10 * time.Minute)}
	if !isEdgeStale(stale) {
		t.Error("old edge should be stale")
	}

	zero := core.PrivilegeEdge{}
	if !isEdgeStale(zero) {
		t.Error("zero-time edge should be stale")
	}
}
