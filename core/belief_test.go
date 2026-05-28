package core

import (
	"math"
	"testing"
)

func TestBayesianUpdate_preservesHighConfidence(t *testing.T) {
	after := BayesianUpdate(0.90, true, float64(ChannelLdapScan))
	if after < 0.90 {
		t.Fatalf("LDAP should strengthen confidence, got %f", after)
	}
	if after >= 1.0 {
		t.Fatal("should not reach 1.0")
	}
}

func TestBayesianUpdate_degradesOnFailure(t *testing.T) {
	after := BayesianUpdate(0.90, false, float64(ChannelLdapScan))
	if after > 0.50 {
		t.Fatalf("LDAP failure should crater confidence, got %f", after)
	}
}

func TestBayesianUpdate_weakChannelSmallMovement(t *testing.T) {
	after := BayesianUpdate(0.60, true, float64(ChannelHeuristic))
	// Heuristic channel (0.60) produces weak evidence — posterior should
	// still increase but stay bounded
	if after < 0.60 {
		t.Fatal("weak pass should not decrease confidence")
	}
	if after > 0.75 {
		t.Fatalf("weak channel should not boost far past prior, got %f", after)
	}
}

func TestBayesianUpdate_lowPriorRecoversOnStrongEvidence(t *testing.T) {
	after := BayesianUpdate(0.20, true, float64(ChannelLdapScan))
	if after < 0.70 {
		t.Fatalf("LDAP should recover low prior strongly, got %f", after)
	}
}

func TestBayesianUpdate_degeneratePriorClamped(t *testing.T) {
	after := BayesianUpdate(0, true, float64(ChannelLdapScan))
	if after <= 0 {
		t.Fatal("zero prior should be clamped")
	}
}

func TestBayesianUpdate_zeroChannelPassTanksConfidence(t *testing.T) {
	// A channel with reliability=0 that says "passed" is a strong
	// false-positive signal: P(obs|valid) = 0. Posterior should crash.
	after := BayesianUpdate(0.50, true, 0)
	if after > 0.01 {
		t.Fatalf("zero-reliability sensor pass should tank confidence, got %f", after)
	}
}

func TestBayesianUpdate_failureWeakChannelSoftDegrade(t *testing.T) {
	after := BayesianUpdate(0.70, false, float64(ChannelHeuristic))
	if after < 0.40 {
		t.Fatalf("weak channel fail should not crater, got %f", after)
	}
}

func TestBayesianUpdate_failureStrongChannelHardDegrade(t *testing.T) {
	after := BayesianUpdate(0.70, false, float64(ChannelLdapScan))
	if after > 0.30 {
		t.Fatalf("authoritative channel fail should crater, got %f", after)
	}
}

func TestBayesianUpdate_consecutivePassesConverge(t *testing.T) {
	p := 0.50
	for i := 0; i < 10; i++ {
		p = BayesianUpdate(p, true, float64(ChannelToolOutput))
	}
	if p < 0.95 {
		t.Fatalf("consecutive passes should converge near 1.0, got %f", p)
	}
}

func TestBayesianUpdate_consecutiveFailuresConverge(t *testing.T) {
	p := 0.50
	for i := 0; i < 10; i++ {
		p = BayesianUpdate(p, false, float64(ChannelToolOutput))
	}
	if p > 0.05 {
		t.Fatalf("consecutive failures should converge near 0.0, got %f", p)
	}
}

func TestBalancedUpdate_passed(t *testing.T) {
	// Balanced channel at 0.50 means "no information" — posterior = prior
	after := BayesianUpdate(0.70, true, 0.50)
	diff := math.Abs(after - 0.70)
	if diff > 0.01 {
		t.Fatalf("balanced channel shouldn't move belief, got %f (diff %f)", after, diff)
	}
}

func TestBayesianDecay_noElapsed(t *testing.T) {
	d := BayesianDecay(0.90, 0, 3600)
	if d != 0.90 {
		t.Fatalf("no elapsed should preserve belief, got %f", d)
	}
}

func TestBayesianDecay_atHalfLife(t *testing.T) {
	d := BayesianDecay(0.90, 3600, 3600)
	expected := 0.3 + (0.90-0.30)*0.5
	if math.Abs(d-expected) > 0.01 {
		t.Fatalf("expected ~%f, got %f", expected, d)
	}
}

func TestBayesianDecay_longElapsed(t *testing.T) {
	d := BayesianDecay(0.90, 3600*24, 3600)
	// After 24 half-lives, decay factor is 2^(-24) ~ 6e-8, so effectively at floor
	if d > 0.35 {
		t.Fatalf("should decay near floor after many half-lives, got %f", d)
	}
}

func TestBayesianDecay_floor(t *testing.T) {
	d := BayesianDecay(0.30, 3600, 3600)
	if d != 0.30 {
		t.Fatalf("at floor already, should stay at floor, got %f", d)
	}
}
