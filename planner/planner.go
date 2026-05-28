package planner

import (
	"container/heap"
	"sort"
	"strconv"
	"strings"
	"time"

	"adpack/core"
)

// PlannerConfig controls how the weighted planner scores and prunes paths.
// The cost model evaluates each edge as a multi-dimensional ScoreVector
// (OperationalCost, DetectionRisk, ExecutionRisk, ToolingGap) which the
// active Policy then projects to a scalar via its projection function.
// Policies may apply categorical filters (e.g. forbid DCSync under stealth)
// and non-linear penalties (e.g. quadratic noise cost).
type PlannerConfig struct {
	AvailableCaps []string
	NoiseLimit    float64 // overrides policy default if > 0
	MaxPaths      int
	MaxDepth      int
	Policy        Policy
}

// ScoredPath is a ranked plan from a start principal to a high-value target.
// Lower TotalCost is better.
type ScoredPath struct {
	Steps       []core.PrivilegeEdge
	TotalCost   float64
	TotalWeight float64
	TotalNoise  float64
	NeededCaps  []string
	Target      string
}

// DefaultConfig returns sensible defaults for an aggressive engagement.
func DefaultConfig() PlannerConfig {
	return PlannerConfig{
		NoiseLimit: 1.0,
		MaxPaths:   10,
		MaxDepth:   12,
		Policy:     PolicySpeed,
	}
}

// confidencePenalty returns a cost addend proportional to (1 - confidence).
// The planner naturally prefers higher-confidence paths without categorically
// excluding low-confidence ones.
func confidencePenalty(confidence float64) float64 {
	return (1.0 - confidence) * 5.0
}

// stalePenalty returns a fixed cost addend for edges that have not been
// re-verified recently. The staleness window is one hour by default.
func stalePenalty(e core.PrivilegeEdge) float64 {
	if e.Stale(time.Hour) {
		return 3.0
	}
	return 0.0
}

// Planner wraps state and configuration for weighted privilege path planning.
// It caches the adjacency list for repeated PlanPaths calls from different
// start principals.
type Planner struct {
	state *core.ADState
	cfg   PlannerConfig
	adj   map[string][]core.PrivilegeEdge
}

// New creates a planner over the given state with the given config.
func New(state *core.ADState, cfg PlannerConfig) *Planner {
	if cfg.MaxPaths <= 0 {
		cfg.MaxPaths = 10
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 12
	}

	// Build adjacency list
	adj := make(map[string][]core.PrivilegeEdge)
	for _, e := range state.Edges {
		key := e.Domain + "\\" + e.SourcePrincipal
		adj[key] = append(adj[key], e)
	}

	return &Planner{state: state, cfg: cfg, adj: adj}
}

// dijkstraNode is the priority-queue entry for the weighted planner.
type dijkstraNode struct {
	principal string
	cost      float64
	weight    float64
	noise     float64
	path      []core.PrivilegeEdge
	needed    map[string]bool
	pathCtx   PathContext // accumulated path state for path-dependent evaluation
	index     int
}

type priorityQueue []*dijkstraNode

func (pq priorityQueue) Len() int           { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool { return pq[i].cost < pq[j].cost }
func (pq priorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i]; pq[i].index = i; pq[j].index = j }
func (pq *priorityQueue) Push(x any) {
	n := x.(*dijkstraNode)
	n.index = len(*pq)
	*pq = append(*pq, n)
}
func (pq *priorityQueue) Pop() any {
	old := *pq
	n := old[len(old)-1]
	old[len(old)-1] = nil
	n.index = -1
	*pq = old[:len(old)-1]
	return n
}

// effectiveNoiseLimit returns the noise limit, preferring explicit config
// over the policy default.
func (p *Planner) effectiveNoiseLimit() float64 {
	if p.cfg.NoiseLimit > 0 {
		return p.cfg.NoiseLimit
	}
	return p.cfg.Policy.NoiseLimit()
}

// preconditionsMet checks whether all execution preconditions for an edge are
// satisfied by the current execution state. Returns true when there are no
// preconditions or all are satisfied. Unknown precondition kinds are treated as
// satisfied (open-world assumption for forward compatibility).
func (p *Planner) preconditionsMet(edge core.PrivilegeEdge) bool {
	for _, pc := range edge.Preconditions {
		switch pc.Kind {
		case core.PrecondPortOpen:
			if !p.portOpen(pc.Target, pc.Port) {
				return false
			}
		case core.PrecondProtocolReachable:
			if !p.state.Exec.ReachableHosts[pc.Target] {
				return false
			}
		case core.PrecondAuthWorks:
			if !p.state.Exec.ValidCreds[pc.Target] {
				return false
			}
		case core.PrecondPrivilegeHeld:
			if !p.state.Exec.ValidCreds[pc.Target] {
				return false
			}
		}
	}
	return true
}

func (p *Planner) portOpen(target string, port int) bool {
	for _, openPort := range p.state.Exec.OpenPorts[target] {
		if openPort == port {
			return true
		}
	}
	portString := strconv.Itoa(port)
	for _, host := range p.state.Hosts {
		if host.IP != target && !strings.EqualFold(host.Hostname, target) {
			continue
		}
		for _, token := range strings.Split(host.PortsOpen, ",") {
			if strings.TrimSpace(token) == portString {
				return true
			}
		}
	}
	return false
}

// it to a scalar cost using the active policy's projection function. The
// PathContext carries accumulated path state for path-dependent evaluation
// (cumulative detection risk, repeated technique penalties, etc.).
// Active services in RuntimeState reduce tooling gaps for matching edges.
// Returns (cost, true) when the edge is usable, or (0, false) when the policy
// categorically excludes it (e.g. DCSync under stealth).
func (p *Planner) edgeCost(e core.PrivilegeEdge, capSet map[string]bool, ctx PathContext) (float64, bool) {
	v := edgeToVector(e, capSet)

	// If an active service covers any of the edge's requirements, reduce tooling gap.
	if v.ToolingGap > 0 && len(p.state.Runtime.ActiveServices) > 0 {
		for _, svc := range p.state.Runtime.ActiveServices {
			if !svc.IsRunning() {
				continue
			}
			for _, req := range e.Requires {
				if string(svc.Type) == req || svc.ID == req {
					// Service is already running — tooling requirement is partially met
					v.ToolingGap -= 0.3
					if v.ToolingGap < 0 {
						v.ToolingGap = 0
					}
				}
			}
		}
	}
	proj := getProjection(p.cfg.Policy)
	cost, ok := proj(v, e, ctx)
	if !ok {
		return 0, false
	}
	// Confidence and staleness penalties are applied to every edge regardless
	// of policy. Low-confidence edges get a cost bump; stale edges get an
	// additional bump. This makes the planner naturally prefer recently-
	// verified, high-confidence paths without categorically excluding them.
	cost += confidencePenalty(e.Confidence)
	cost += stalePenalty(e)
	return cost, true
}

// highValueTargets returns the set of principal keys that are high-value
// targets (DA users, DC computers, admin groups, AdminSDHolder, SYSTEM@host).
func (p *Planner) highValueTargets() (map[string]bool, map[string]bool) {
	highValue := make(map[string]bool)
	for _, u := range p.state.Users {
		if u.IsDA {
			highValue[u.Domain+"\\"+u.Username] = true
		}
	}
	for _, c := range p.state.Computers {
		if c.IsDC {
			highValue[c.Domain+"\\"+c.Name+"$"] = true
		}
	}
	highValueNames := map[string]bool{
		"Domain Admins":      true,
		"domain admins":      true,
		"DOMAIN ADMINS":      true,
		"Enterprise Admins":  true,
		"enterprise admins":  true,
		"ENTERPRISE ADMINS":  true,
		"Administrators":     true,
		"administrators":     true,
		"ADMINISTRATORS":     true,
		"Domain Controllers": true,
		"domain controllers": true,
		"DOMAIN CONTROLLERS": true,
		"AdminSDHolder":      true,
		"adminsdholder":      true,
		"ADMINSDHOLDER":      true,
	}
	for _, g := range p.state.Groups {
		if highValueNames[g.Name] {
			highValue[g.Domain+"\\"+g.Name] = true
		}
	}
	return highValue, highValueNames
}

// PlanPaths performs weighted shortest-path search (Dijkstra) over the
// privilege edge graph. Returns up to cfg.MaxPaths paths ranked by total cost.
//
// Cost model: each edge is evaluated as a multi-dimensional ScoreVector
// (OperationalCost, DetectionRisk, ExecutionRisk, ToolingGap) and projected
// to a scalar via the active policy's projection function. Policies may
// apply categorical exclusions (e.g. DCSync under stealth) and non-linear
// penalties (e.g. quadratic noise cost).
func (p *Planner) PlanPaths(startPrincipal string) []ScoredPath {
	highValue, highValueNames := p.highValueTargets()

	isHighValue := func(principal string) bool {
		if highValue[principal] {
			return true
		}
		// Check bare principal string for SYSTEM@ (no domain prefix)
		if strings.HasPrefix(principal, "SYSTEM@") {
			return true
		}
		// Check after any Domain\ prefix (planner prepends Domain\ to target keys)
		_, after, hasSep := strings.Cut(principal, "\\")
		if hasSep && strings.HasPrefix(after, "SYSTEM@") {
			return true
		}
		_, name, ok := strings.Cut(principal, "\\")
		if ok && highValueNames[name] {
			return true
		}
		return false
	}

	// Build capability set for O(1) lookup
	capSet := make(map[string]bool)
	for _, c := range p.cfg.AvailableCaps {
		capSet[c] = true
	}

	// Dijkstra
	bestCost := make(map[string]float64)
	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &dijkstraNode{
		principal: startPrincipal,
		cost:      0,
		path:      []core.PrivilegeEdge{},
		needed:    make(map[string]bool),
		pathCtx:   emptyPathContext(),
	})

	var results []ScoredPath
	foundTargets := make(map[string]bool)

	for pq.Len() > 0 && len(results) < p.cfg.MaxPaths {
		node := heap.Pop(pq).(*dijkstraNode)

		if len(node.path) >= p.cfg.MaxDepth {
			continue
		}

		// If we've already found a better path to this node, skip
		if bc, ok := bestCost[node.principal]; ok && node.cost > bc {
			continue
		}

		if isHighValue(node.principal) && len(node.path) > 0 {
			if !foundTargets[node.principal] {
				foundTargets[node.principal] = true
				var caps []string
				for c := range node.needed {
					caps = append(caps, c)
				}
				sort.Strings(caps)
				results = append(results, ScoredPath{
					Steps:       append([]core.PrivilegeEdge(nil), node.path...),
					TotalCost:   node.cost,
					TotalWeight: node.weight,
					TotalNoise:  node.noise,
					NeededCaps:  caps,
					Target:      node.principal,
				})
			}
			continue
		}

		for _, edge := range p.adj[node.principal] {
			targetKey := edge.Domain + "\\" + edge.TargetPrincipal

			// Compute path context for path-dependent policy evaluation
			newCtx := extendPathContext(node.pathCtx, edge)

			// Evaluate edge cost through policy projection, with path context
			edgeCost, ok := p.edgeCost(edge, capSet, newCtx)
			if !ok {
				// Policy categorically excludes this edge (e.g. DCSync under stealth)
				continue
			}

			// Prune by execution preconditions
			if !p.preconditionsMet(edge) {
				continue
			}

			// Prune by noise limit
			maxStepNoise := node.noise
			if edge.Noise > maxStepNoise {
				maxStepNoise = edge.Noise
			}
			if maxStepNoise > p.effectiveNoiseLimit() {
				continue
			}

			newCost := node.cost + edgeCost
			if bc, ok := bestCost[targetKey]; ok && newCost >= bc {
				continue
			}
			bestCost[targetKey] = newCost

			needed := make(map[string]bool)
			for k, v := range node.needed {
				needed[k] = v
			}
			for _, req := range edge.Requires {
				if !capSet[req] {
					needed[req] = true
				}
			}

			newPath := make([]core.PrivilegeEdge, len(node.path)+1)
			copy(newPath, node.path)
			newPath[len(node.path)] = edge

			heap.Push(pq, &dijkstraNode{
				principal: targetKey,
				cost:      newCost,
				weight:    node.weight + edge.Weight,
				noise:     maxStepNoise,
				path:      newPath,
				needed:    needed,
				pathCtx:   newCtx,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].TotalCost < results[j].TotalCost })
	return results
}
