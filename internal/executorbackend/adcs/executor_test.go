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

	edge := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\user",
		TargetPrincipal: "CA-SERVER",
		AccessRight:     "ESC1",
		Domain:          "DOMAIN",
		ObservedAt:      time.Now(),
	}
	_ = e.CanExecute(ctx, edge, state)

	stale := edge
	stale.ObservedAt = time.Now().Add(-10 * time.Minute)
	_ = e.CanExecute(ctx, stale, state)

	empty := core.PrivilegeEdge{}
	_ = e.CanExecute(ctx, empty, state)
}

func TestPKINITAuthCanExecute(t *testing.T) {
	e := &PKINITAuthExecutor{}
	ctx := context.Background()
	state := &core.ADState{}

	edge := core.PrivilegeEdge{
		SourcePrincipal: "DOMAIN\\user",
		TargetPrincipal: "DOMAIN\\DA",
		AccessRight:     "HasCertificate",
		EdgeType:        "adcs_cert",
		Domain:          "DOMAIN",
		ObservedAt:      time.Now(),
		Requires:        []string{"has_pfx"},
	}
	_ = e.CanExecute(ctx, edge, state)

	noPfx := edge
	noPfx.Requires = nil
	_ = e.CanExecute(ctx, noPfx, state)

	wrongAr := edge
	wrongAr.AccessRight = "GenericAll"
	_ = e.CanExecute(ctx, wrongAr, state)
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
