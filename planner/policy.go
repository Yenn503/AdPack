package planner

import "adpack/core"

// Policy controls edge evaluation and cost projection.
// Each policy encodes a different operational preference (stealth, speed,
// reliability, or minimal tooling footprint).
type Policy string

const (
	PolicySpeed          Policy = "speed"
	PolicyStealth        Policy = "stealth"
	PolicyReliability    Policy = "reliability"
	PolicyMinimalTooling Policy = "minimal_tooling"
)

// ScoreVector is the multi-dimensional evaluation of an edge's operational
// characteristics. Each dimension is normalised so higher = worse.
// This is the intermediate representation before policy projection —
// policies differ in how they weight each dimension, not in the
// dimensions themselves.
type ScoreVector struct {
	OperationalCost float64 // base difficulty (derived from Weight)
	DetectionRisk   float64 // how detectable (derived from Noise)
	ExecutionRisk   float64 // how likely to fail (1.0 - Exploitability)
	ToolingGap      float64 // missing capability penalty (0-1 fraction)
}

// PathContext carries accumulated path state for path-dependent policy
// evaluation. Operational risk is often path-dependent, not edge-local:
// three medium-noise edges may be worse than one very noisy edge,
// and repeated techniques compound detection probability.
type PathContext struct {
	StepCount       int      // number of edges traversed so far in this path
	CumulativeNoise float64  // sum of detection risk across all edges
	MaxNoise        float64  // worst single-edge noise
	PreviousRights  []string // access rights used in this path
}

// edgeToVector evaluates an edge's operational characteristics across all
// ScoreVector dimensions. This is policy-agnostic — it produces the raw
// multi-dimensional profile that each policy will project differently.
func edgeToVector(e core.PrivilegeEdge, capSet map[string]bool) ScoreVector {
	toolGap := 0.0
	if len(e.Requires) > 0 {
		missing := 0
		for _, req := range e.Requires {
			if !capSet[req] {
				missing++
			}
		}
		toolGap = float64(missing) / float64(len(e.Requires))
	}

	execRisk := 1.0 - e.Exploitability
	if execRisk < 0 {
		execRisk = 0
	}

	return ScoreVector{
		OperationalCost: e.Weight,
		DetectionRisk:   e.Noise,
		ExecutionRisk:   execRisk,
		ToolingGap:      toolGap,
	}
}

// extendPathContext computes the PathContext for a path after adding newEdge.
func extendPathContext(prev PathContext, newEdge core.PrivilegeEdge) PathContext {
	ctx := PathContext{
		StepCount:       prev.StepCount + 1,
		CumulativeNoise: prev.CumulativeNoise + newEdge.Noise,
		MaxNoise:        prev.MaxNoise,
		PreviousRights:  append(append([]string{}, prev.PreviousRights...), newEdge.AccessRight),
	}
	if newEdge.Noise > ctx.MaxNoise {
		ctx.MaxNoise = newEdge.Noise
	}
	return ctx
}

// emptyPathContext is the starting context before any edge is traversed.
func emptyPathContext() PathContext {
	return PathContext{}
}

// projection is a policy-specific function that maps an edge's ScoreVector to
// a scalar cost for Dijkstra traversal. The PathContext carries accumulated
// path state so projections can model cumulative detection risk, repeated
// technique penalties, and host-touch costs.
//
// The returned bool is false when the edge should be categorically excluded
// (e.g. DCSync under stealth). A false return means the edge is
// *operationally forbidden*, not merely expensive.
type projection func(v ScoreVector, e core.PrivilegeEdge, ctx PathContext) (cost float64, ok bool)

// DefaultCapPenalty is the base cost added per missing capability.
const DefaultCapPenalty = 10.0

// projections maps each policy to its cost projection function.
var projections = map[Policy]projection{
	PolicySpeed: func(v ScoreVector, e core.PrivilegeEdge, ctx PathContext) (float64, bool) {
		// Speed: path length adds marginal failure risk
		stepPenalty := float64(ctx.StepCount) * 0.5
		return v.OperationalCost*1.0 + v.DetectionRisk*0.5 + v.ToolingGap*DefaultCapPenalty*0.5 + stepPenalty, true
	},
	PolicyStealth: func(v ScoreVector, e core.PrivilegeEdge, ctx PathContext) (float64, bool) {
		// Categorically exclude DCSync — it's too noisy for stealth ops
		if e.AccessRight == "DCSync" {
			return 0, false
		}
		// Quadratic noise penalty for the current edge
		noisePenalty := v.DetectionRisk * v.DetectionRisk * 5.0
		// Cumulative noise penalty: compound detection risk across path
		cumPenalty := ctx.CumulativeNoise * ctx.CumulativeNoise * 0.3
		// Repeated technique penalty: same right used twice is riskier
		repeatPenalty := 0.0
		for _, r := range ctx.PreviousRights {
			if r == e.AccessRight {
				repeatPenalty += 3.0
			}
		}
		return v.OperationalCost*1.0 + noisePenalty + cumPenalty + repeatPenalty + v.ToolingGap*DefaultCapPenalty*1.0, true
	},
	PolicyReliability: func(v ScoreVector, e core.PrivilegeEdge, ctx PathContext) (float64, bool) {
		// Skip low-confidence edges entirely
		if e.Confidence < 0.7 {
			return 0, false
		}
		// Each additional step multiplies failure probability
		stepRisk := float64(ctx.StepCount) * v.ExecutionRisk * 2.0
		return v.OperationalCost*1.0 + v.DetectionRisk*1.0 + v.ExecutionRisk*3.0 + stepRisk + v.ToolingGap*DefaultCapPenalty*2.0, true
	},
	PolicyMinimalTooling: func(v ScoreVector, e core.PrivilegeEdge, ctx PathContext) (float64, bool) {
		// Categorically exclude edges requiring unavailable tools
		if v.ToolingGap > 0 {
			return 0, false
		}
		return v.OperationalCost*1.0 + v.DetectionRisk*1.0, true
	},
}

// getProjection returns the projection function for a policy.
func getProjection(p Policy) projection {
	proj, ok := projections[p]
	if !ok {
		return func(v ScoreVector, e core.PrivilegeEdge, ctx PathContext) (float64, bool) {
			return v.OperationalCost*1.0 + v.DetectionRisk*1.0 + v.ToolingGap*DefaultCapPenalty, true
		}
	}
	return proj
}

// NoiseLimit returns the maximum acceptable noise for this policy.
func (p Policy) NoiseLimit() float64 {
	switch p {
	case PolicyStealth:
		return 0.9
	case PolicyReliability:
		return 1.0
	default:
		return 1.0
	}
}

// ConfidenceCutoff returns the minimum edge confidence required for this policy.
func (p Policy) ConfidenceCutoff() float64 {
	switch p {
	case PolicyReliability:
		return 0.7
	case PolicyStealth:
		return 0.3
	default:
		return 0.0
	}
}
