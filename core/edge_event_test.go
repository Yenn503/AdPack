package core

import (
	"math"
	"testing"
	"time"
)

func TestReduceEdgeEvent_Observed(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.0}
	ev := EdgeEvent{Type: EventObserved, Confidence: 0.7, Method: "bloodhound", Timestamp: time.Now()}
	updated, vol := ReduceEdgeEvent(e, ev)
	if updated.Confidence != 0.7 {
		t.Fatalf("expected confidence 0.7, got %.2f", updated.Confidence)
	}
	if updated.ValidationState != EdgeObserved {
		t.Fatalf("expected EdgeObserved, got %s", updated.ValidationState)
	}
	if vol != 0.7 {
		t.Fatalf("expected volatility 0.7, got %.2f", vol)
	}
}

func TestReduceEdgeEvent_Verified(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.3}
	ev := EdgeEvent{Type: EventVerified, Confidence: 0.9, Method: "ldap_memberOf", Timestamp: time.Now()}
	updated, _ := ReduceEdgeEvent(e, ev)
	// BayesianUpdate(0.3, true, ChannelLdapScan=0.95) ≈ 0.89
	if updated.Confidence < 0.85 || updated.Confidence > 0.92 {
		t.Fatalf("expected confidence ~0.89, got %.4f", updated.Confidence)
	}
	if updated.ValidationState != EdgeValidated {
		t.Fatalf("expected EdgeValidated, got %s", updated.ValidationState)
	}
}

func TestReduceEdgeEvent_Degraded(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.85}
	ev := EdgeEvent{Type: EventDegraded, Confidence: 0.15, Method: "ldap_memberOf", Timestamp: time.Now()}
	updated, _ := ReduceEdgeEvent(e, ev)
	// BayesianUpdate(0.85, false, ChannelLdapScan=0.95) ≈ 0.23
	want := 0.23
	if math.Abs(updated.Confidence-want) > 0.01 {
		t.Fatalf("expected confidence ~%.2f, got %.4f", want, updated.Confidence)
	}
	if updated.ValidationState != EdgeDegraded {
		t.Fatalf("expected EdgeDegraded, got %s", updated.ValidationState)
	}
	if updated.VerificationMethod != "degraded:ldap_memberOf" {
		t.Fatalf("expected 'degraded:ldap_memberOf', got %s", updated.VerificationMethod)
	}
}

func TestReduceEdgeEvent_DegradedDoesNotIncrease(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.3}
	ev := EdgeEvent{Type: EventDegraded, Confidence: 0.7, Method: "ldap_memberOf", Timestamp: time.Now()}
	updated, _ := ReduceEdgeEvent(e, ev)
	// BayesianUpdate(0.3, false, ChannelLdapScan=0.95) ≈ 0.02
	if updated.Confidence >= 0.3 {
		t.Fatalf("expected confidence to decrease from 0.3, got %.4f", updated.Confidence)
	}
}

func TestReduceEdgeEvent_RecheckedPass(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.2, ValidationState: EdgeDegraded}
	ev := EdgeEvent{Type: EventReChecked, Confidence: 0.9, Method: "ldap_scan", Timestamp: time.Now()}
	updated, _ := ReduceEdgeEvent(e, ev)
	// BayesianUpdate(0.2, true, ChannelLdapScan=0.95) ≈ 0.83
	want := 0.826
	if math.Abs(updated.Confidence-want) > 0.01 {
		t.Fatalf("expected confidence ~%.3f, got %.4f", want, updated.Confidence)
	}
	if updated.ValidationState != EdgeValidated {
		t.Fatalf("expected EdgeValidated after recheck pass, got %s", updated.ValidationState)
	}
}

func TestReduceEdgeEvent_RecheckedFail(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.2, ValidationState: EdgeDegraded}
	ev := EdgeEvent{Type: EventReChecked, Confidence: 0.3, Method: "ldap_scan", Timestamp: time.Now()}
	updated, _ := ReduceEdgeEvent(e, ev)
	// BayesianUpdate(0.2, false, ChannelLdapScan=0.95) ≈ 0.013
	if updated.Confidence > 0.02 {
		t.Fatalf("expected confidence near zero after authoritative fail, got %.4f", updated.Confidence)
	}
	if updated.ValidationState != EdgeDegraded {
		t.Fatalf("expected EdgeDegraded after recheck fail, got %s", updated.ValidationState)
	}
}

func TestReduceEdgeEvent_Failed(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.8}
	ev := EdgeEvent{Type: EventFailed, Method: "connection_timeout", Timestamp: time.Now()}
	updated, _ := ReduceEdgeEvent(e, ev)
	// "connection_timeout" → ChannelEnumeration=0.70
	// BayesianUpdate(0.8, false, 0.70) ≈ 0.6316
	want := 0.6316
	if math.Abs(updated.Confidence-want) > 0.001 {
		t.Fatalf("expected confidence %.4f, got %.4f", want, updated.Confidence)
	}
	if updated.ValidationState != EdgeDegraded {
		t.Fatalf("expected EdgeDegraded after failure, got %s", updated.ValidationState)
	}
}

func TestReduceEdgeEvent_Volatility(t *testing.T) {
	tests := []struct {
		prev     float64
		evConf   float64
		method   string
		wantLow  float64
		wantHigh float64
	}{
		// BayesianUpdate(0.9, false, default=0.70) ≈ 0.794 → volatility ≈ 0.106
		{0.9, 0.1, "test", 0.10, 0.11},
		// BayesianUpdate(0.5, false, default=0.70) = 0.30 → volatility = 0.20
		{0.5, 0.5, "test", 0.19, 0.21},
		// BayesianUpdate(0.3, true, default=0.70) = 0.50 → volatility = 0.20
		{0.3, 0.85, "test", 0.19, 0.21},
	}
	for _, tt := range tests {
		e := PrivilegeEdge{Confidence: tt.prev}
		ev := EdgeEvent{Type: EventReChecked, Confidence: tt.evConf, Method: tt.method, Timestamp: time.Now()}
		_, vol := ReduceEdgeEvent(e, ev)
		if vol < tt.wantLow || vol > tt.wantHigh {
			t.Errorf("ReduceEdgeEvent(prev=%.2f, ev=%.2f) volatility = %.4f, want [%.2f, %.2f]",
				tt.prev, tt.evConf, vol, tt.wantLow, tt.wantHigh)
		}
	}
}

func TestDriftScore_staleNoVolatility(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.9}
	// Zero LastVerifiedAt → stale: 1.0*2.0 + 0.1*3.0 + 0*5 = 2.3
	score := DriftScore(e, 0.0, time.Hour)
	if score < 2.29 || score > 2.31 {
		t.Fatalf("expected drift score ~2.3 for stale edge, got %.6f", score)
	}
}

func TestDriftScore_freshEdge(t *testing.T) {
	e := PrivilegeEdge{
		Confidence:     0.95,
		LastVerifiedAt: time.Now(),
	}
	score := DriftScore(e, 0.0, time.Hour)
	if score < 0.149 || score > 0.151 {
		// staleness=0*2 + (1-0.95)*3 + 0*5 ≈ 0.15
		t.Fatalf("expected drift score ~0.15, got %.6f", score)
	}
}

func TestDriftScore_volatile(t *testing.T) {
	e := PrivilegeEdge{
		Confidence:     0.5,
		LastVerifiedAt: time.Now(),
	}
	score := DriftScore(e, 0.4, time.Hour)
	// 0.0*2.0 + 0.5*3.0 + 0.4*5.0 = 3.5
	if score < 3.49 || score > 3.51 {
		t.Fatalf("expected drift score ~3.5, got %.6f", score)
	}
}

func TestDriftScore_staleAndVolatile(t *testing.T) {
	e := PrivilegeEdge{Confidence: 0.3} // zero LastVerifiedAt → stale
	score := DriftScore(e, 0.6, time.Hour)
	// 1.0*2.0 + 0.7*3.0 + 0.6*5.0 = 7.1
	if score < 7.09 || score > 7.11 {
		t.Fatalf("expected drift score ~7.1, got %.6f", score)
	}
}
