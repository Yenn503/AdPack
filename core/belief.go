package core

import "math"

// ChannelReliability encodes how trustworthy each observation method is.
type ChannelReliability float64

const (
	ChannelLdapScan    ChannelReliability = 0.95
	ChannelToolOutput  ChannelReliability = 0.80
	ChannelHeuristic   ChannelReliability = 0.60
	ChannelEnumeration ChannelReliability = 0.70
	ChannelExecutor    ChannelReliability = 0.90
)

// BayesianUpdate computes P(valid | observation) via Bayes' theorem.
//
//	P(valid | obs) = P(obs | valid) * P(valid) / P(obs)
//
// passed=true:  likelihood = channelReliability
// passed=false: likelihood = 1 - channelReliability
func BayesianUpdate(belief float64, passed bool, channelReliability float64) float64 {
	if belief <= 0 {
		belief = 0.001
	}
	if belief >= 1 {
		belief = 0.999
	}
	if channelReliability <= 0 {
		channelReliability = 0.001
	}
	if channelReliability >= 1 {
		channelReliability = 0.999
	}

	likelihood := channelReliability
	if !passed {
		likelihood = 1.0 - channelReliability
	}

	pInvalid := 1.0 - belief
	denom := likelihood*belief + (1.0-likelihood)*pInvalid
	if denom <= 0 {
		return belief
	}
	return (likelihood * belief) / denom
}

// BayesianDecay discounts belief toward floor using exponential decay.
//
//	P(t) = floor + (P0 - floor) * 2^(-t / halfLife)
//
// This models confidence erosion as time passes without observation.
func BayesianDecay(belief float64, elapsedSeconds float64, halfLifeSeconds float64) float64 {
	if halfLifeSeconds <= 0 {
		return belief
	}
	floor := 0.3
	if elapsedSeconds <= 0 {
		return belief
	}
	ratio := elapsedSeconds / halfLifeSeconds
	decay := math.Pow(0.5, ratio)
	return floor + (belief-floor)*decay
}
