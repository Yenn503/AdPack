package modules

import (
	"context"
	"fmt"

	"adpack/core"
)

// FixpointConfig controls convergence behaviour.
type FixpointConfig struct {
	MaxIterations int
}

// DefaultFixpointConfig returns sensible convergence limits.
func DefaultFixpointConfig() FixpointConfig {
	return FixpointConfig{MaxIterations: 10}
}

// FixpointResult captures what the convergence loop discovered.
type FixpointResult struct {
	Iterations   int
	EdgesAdded   int
	TotalBefore  int
	TotalAfter   int
	PerIteration []int
	DidConverge  bool
}

// RunFixpoint iterates the executor registry over all current edges,
// applying predicted deltas until no new edges emerge (quiescence).
//
// This is a pure graph rewrite — it calls Execute() on each executor for
// each eligible edge but does NOT run real tools. The loop converges when
// the executor layer cannot produce any novel edge from the current state.
//
// The fixpoint gives the planner maximal visibility: every edge that could
// theoretically be produced is already present before routing decisions.
func RunFixpoint(ctx context.Context, state *core.ADState, registry *core.CapabilityRegistry, cfg FixpointConfig) FixpointResult {
	before := len(state.Edges)
	totalAdded := 0
	perIter := []int{}

	// Work on a snapshot: cloned edges list grows each iteration, but we
	// only consider pre-iteration edges as sources to keep convergence
	// bounded and predictable (one rewrite pass per iteration).
	edgePool := make([]core.PrivilegeEdge, len(state.Edges))
	copy(edgePool, state.Edges)

	for iter := 0; iter < cfg.MaxIterations; iter++ {
		select {
		case <-ctx.Done():
			return FixpointResult{
				Iterations: iter, EdgesAdded: totalAdded,
				TotalBefore: before, TotalAfter: len(state.Edges),
				PerIteration: perIter, DidConverge: false,
			}
		default:
		}

		addedThis := 0
		var newEdges []core.PrivilegeEdge

		for _, e := range edgePool {
			cap := core.AccessRightToCapability(e)
			exec, status := registry.Resolve(cap)
			if status != core.CapabilityAvailable {
				continue
			}
			if !exec.CanExecute(ctx, e, state) {
				continue
			}

			result := exec.Execute(ctx, e, state)
			if len(result.Delta.NewEdges) == 0 {
				continue
			}

			for _, ne := range result.Delta.NewEdges {
				already := false
				for _, existing := range state.Edges {
					if core.EdgeKeyOf(existing) == core.EdgeKeyOf(ne) {
						already = true
						break
					}
				}
				if !already {
					state.Edges = append(state.Edges, ne)
					newEdges = append(newEdges, ne)
					addedThis++
					totalAdded++
				}
			}
		}

		perIter = append(perIter, addedThis)

		if addedThis == 0 {
			return FixpointResult{
				Iterations: iter + 1, EdgesAdded: totalAdded,
				TotalBefore: before, TotalAfter: len(state.Edges),
				PerIteration: perIter, DidConverge: true,
			}
		}

		// Feed new edges as sources for the next iteration.
		edgePool = newEdges
	}

	return FixpointResult{
		Iterations: cfg.MaxIterations, EdgesAdded: totalAdded,
		TotalBefore: before, TotalAfter: len(state.Edges),
		PerIteration: perIter, DidConverge: false,
	}
}

// FixpointSummary renders a one-line human-readable summary.
func FixpointSummary(r FixpointResult) string {
	status := "converged"
	if !r.DidConverge {
		status = "max iterations reached"
	}
	return fmt.Sprintf("Fixpoint %s: %d iterations, %d edges added (%d → %d), per iteration %v",
		status, r.Iterations, r.EdgesAdded, r.TotalBefore, r.TotalAfter, r.PerIteration)
}
