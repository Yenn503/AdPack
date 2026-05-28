package modules

import (
	"testing"

	"adpack/core"
)

func TestMaterializeCoercerEdge_Success(t *testing.T) {
	evt := core.ServiceEvent{
		Type:    core.EvCoerceSuccess,
		Service: core.ServiceCoercion,
		Data: map[string]any{
			"host":   "kingslanding",
			"method": "SMB",
			"target": "192.168.57.10",
		},
	}

	edge := materializeCoercerEdge(evt)
	if edge == nil {
		t.Fatal("expected non-nil edge")
	}
	if edge.SourcePrincipal != "KINGSLANDING$" {
		t.Errorf("SourcePrincipal = %q, want %q", edge.SourcePrincipal, "KINGSLANDING$")
	}
	if edge.Confidence != 0.8 {
		t.Errorf("Confidence = %v, want 0.8", edge.Confidence)
	}
	if edge.Weight != 4.0 {
		t.Errorf("Weight = %v, want 4.0", edge.Weight)
	}
	if edge.Exploitability != 0.7 {
		t.Errorf("Exploitability = %v, want 0.7", edge.Exploitability)
	}
	if edge.EdgeType != "coercer_auth" {
		t.Errorf("EdgeType = %q, want %q", edge.EdgeType, "coercer_auth")
	}
	if edge.AccessRight != "COERCER_SMB" {
		t.Errorf("AccessRight = %q, want %q", edge.AccessRight, "COERCER_SMB")
	}
	if edge.TargetPrincipal != "192.168.57.10" {
		t.Errorf("TargetPrincipal = %q, want %q", edge.TargetPrincipal, "192.168.57.10")
	}
	if edge.Source != "coercer" {
		t.Errorf("Source = %q, want %q", edge.Source, "coercer")
	}
	if edge.Noise != 0.5 {
		t.Errorf("Noise = %v, want 0.5", edge.Noise)
	}
}

func TestMaterializeCoercerEdge_Attempt(t *testing.T) {
	evt := core.ServiceEvent{
		Type:    core.EvCoerceAttempt,
		Service: core.ServiceCoercion,
		Data: map[string]any{
			"host":   "kingslanding",
			"method": "",
			"target": "192.168.57.10",
		},
	}

	edge := materializeCoercerEdge(evt)
	if edge == nil {
		t.Fatal("expected non-nil edge")
	}
	if edge.Confidence != 0.4 {
		t.Errorf("Confidence = %v, want 0.4", edge.Confidence)
	}
	if edge.Weight != 6.0 {
		t.Errorf("Weight = %v, want 6.0", edge.Weight)
	}
	if edge.Exploitability != 0.5 {
		t.Errorf("Exploitability = %v, want 0.5", edge.Exploitability)
	}
	if edge.EdgeType != "coercer_attempt" {
		t.Errorf("EdgeType = %q, want %q", edge.EdgeType, "coercer_attempt")
	}
	if edge.AccessRight != "COERCER_AUTH" {
		t.Errorf("AccessRight = %q, want %q", edge.AccessRight, "COERCER_AUTH")
	}
}

func TestMaterializeCoercerEdge_UnknownEventType(t *testing.T) {
	evt := core.ServiceEvent{
		Type:    core.EvHashCaptured,
		Service: core.ServiceCoercion,
		Data: map[string]any{
			"host": "kingslanding",
		},
	}

	edge := materializeCoercerEdge(evt)
	if edge != nil {
		t.Fatal("expected nil edge for unknown event type")
	}
}

func TestMaterializeCoercerEdge_MissingHost(t *testing.T) {
	evt := core.ServiceEvent{
		Type:    core.EvCoerceSuccess,
		Service: core.ServiceCoercion,
		Data: map[string]any{
			"target": "192.168.57.10",
		},
	}

	edge := materializeCoercerEdge(evt)
	if edge != nil {
		t.Fatal("expected nil edge when host is missing")
	}
}

func TestMaterializeCoercerEdge_FQDN(t *testing.T) {
	evt := core.ServiceEvent{
		Type:    core.EvCoerceSuccess,
		Service: core.ServiceCoercion,
		Data: map[string]any{
			"host":   "kingslanding.sevenkingdoms.local",
			"method": "LDAP",
			"target": "192.168.57.10",
		},
	}

	edge := materializeCoercerEdge(evt)
	if edge == nil {
		t.Fatal("expected non-nil edge")
	}
	if edge.SourcePrincipal != "KINGSLANDING$" {
		t.Errorf("SourcePrincipal = %q, want %q", edge.SourcePrincipal, "KINGSLANDING$")
	}
	if edge.Domain != "sevenkingdoms.local" {
		t.Errorf("Domain = %q, want %q", edge.Domain, "sevenkingdoms.local")
	}
}
