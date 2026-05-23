package core

import (
	"math"
	"strings"
	"time"
)

type EdgeEventType string

const (
	EventObserved  EdgeEventType = "observed"
	EventVerified  EdgeEventType = "verified"
	EventDegraded  EdgeEventType = "degraded"
	EventReChecked EdgeEventType = "rechecked"
	EventFailed    EdgeEventType = "failed"
	EventDispensed EdgeEventType = "dispensed"
)

// EdgeEvent is a single append-only event in an edge's lifecycle.
type EdgeEvent struct {
	Type       EdgeEventType `json:"type"`
	Timestamp  time.Time     `json:"timestamp"`
	Confidence float64       `json:"confidence"`
	Method     string        `json:"method"`
	Evidence   string        `json:"evidence"`
}

// channelsForMethod maps an event's method string to a channel reliability.
// The method determines how trustworthy the observation is.
func channelsForMethod(method string) float64 {
	if strings.HasPrefix(method, "degraded:") || strings.HasPrefix(method, "failed:") {
		method = method[strings.Index(method, ":")+1:]
	}
	switch {
	case strings.HasPrefix(method, "ldap"):
		return float64(ChannelLdapScan)
	case method == "tool" || method == "executor":
		return float64(ChannelToolOutput)
	case method == "heuristic" || method == "reconcile":
		return float64(ChannelHeuristic)
	default:
		return float64(ChannelEnumeration)
	}
}

// ReduceEdgeEvent applies a Bayesian belief update to an edge from an event.
// This is the single pure function that governs all state transitions.
//
//   - EventObserved: sets initial confidence from the event
//   - EventVerified: BayesianUpdate(passed=true) using method-derived channel
//   - EventDegraded: BayesianUpdate(passed=false) using method-derived channel
//   - EventReChecked: confidence >= 0.7 → pass, else fail
//   - EventFailed: BayesianUpdate(passed=false, ChannelToolOutput)
func ReduceEdgeEvent(e PrivilegeEdge, ev EdgeEvent) (PrivilegeEdge, float64) {
	originalConfidence := e.Confidence

	switch ev.Type {
	case EventObserved:
		if e.Confidence == 0 {
			e.Confidence = clampConfidence(ev.Confidence)
		} else {
			e.Confidence = BayesianUpdate(e.Confidence, true, channelsForMethod(ev.Method))
		}
		e.ValidationState = EdgeObserved
		e.LastVerifiedAt = ev.Timestamp
		e.VerificationMethod = ev.Method

	case EventVerified:
		e.Confidence = BayesianUpdate(e.Confidence, true, channelsForMethod(ev.Method))
		e.ValidationState = EdgeValidated
		e.LastVerifiedAt = ev.Timestamp
		e.VerificationMethod = ev.Method

	case EventDegraded:
		e.Confidence = BayesianUpdate(e.Confidence, false, channelsForMethod(ev.Method))
		e.ValidationState = EdgeDegraded
		e.LastVerifiedAt = ev.Timestamp
		e.VerificationMethod = "degraded:" + ev.Method

	case EventReChecked:
		passed := ev.Confidence >= 0.7
		e.Confidence = BayesianUpdate(e.Confidence, passed, channelsForMethod(ev.Method))
		if passed {
			e.ValidationState = EdgeValidated
		} else {
			e.ValidationState = EdgeDegraded
		}
		e.LastVerifiedAt = ev.Timestamp
		e.VerificationMethod = ev.Method

	case EventFailed:
		e.Confidence = BayesianUpdate(e.Confidence, false, channelsForMethod(ev.Method))
		e.ValidationState = EdgeDegraded
		e.LastVerifiedAt = ev.Timestamp
		e.VerificationMethod = "failed:" + ev.Method
	}

	volatility := math.Abs(e.Confidence - originalConfidence)
	return e, volatility
}

func clampConfidence(c float64) float64 {
	if c <= 0 {
		return 0.001
	}
	if c >= 1 {
		return 0.999
	}
	return c
}

// DriftScore combines staleness, confidence, and volatility into a single
// uncertainty metric. Higher values mean the edge has drifted further from
// its verified state.
func DriftScore(e PrivilegeEdge, volatility float64, staleAfter time.Duration) float64 {
	staleness := 0.0
	if e.Stale(staleAfter) {
		staleness = 1.0
	}
	confPenalty := 1.0 - e.Confidence
	return staleness*2.0 + confPenalty*3.0 + volatility*5.0
}
