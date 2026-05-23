package resolver

import (
	"context"
	"strings"
	"time"

	"adpack/core"
)

// AttachResolverPipeline registers the artifact resolution pipeline on
// the runtime. It reads EvArtifactDiscovered events, dispatches to
// registered resolvers, and emits EvArtifactResolved or EvArtifactResolveFail.
//
// When state is non-nil, resolved artifacts are bridged to graph mutations:
//
//	BuildDeltaFromResolved produces a PostStateDelta, ApplyDelta applies it,
//	and EvEdgeMaterialized is emitted on topology change.
//
// This runs inline in the same goroutine to avoid event channel contention.
func AttachResolverPipeline(ctx context.Context, runtime core.RuntimeProvider, state *core.ADState, resolvers ...ArtifactResolver) {
	go func() {
		for {
			select {
			case evt, ok := <-runtime.Events():
				if !ok {
					return
				}
				if evt.Type != core.EvArtifactDiscovered {
					continue
				}

				artifact := artifactFromEvent(evt)
				if artifact == nil {
					continue
				}

				for _, r := range resolvers {
					if !r.CanHandle(artifact.Type) {
						continue
					}
					resolved, err := r.Resolve(ctx, *artifact)
					if err != nil {
						runtime.Emit(core.ServiceEvent{
							Type:      core.EvArtifactResolveFail,
							ServiceID: evt.ServiceID,
							Service:   core.ServiceResolver,
							Timestamp: time.Now(),
							Data: map[string]any{
								"artifact_type": artifact.Type,
								"resolver_name": r.Name(),
								"error":         err.Error(),
								"path":          artifact.Path,
							},
						})
					} else {
						resolvedEvt := core.ServiceEvent{
							Type:      core.EvArtifactResolved,
							ServiceID: evt.ServiceID,
							Service:   core.ServiceResolver,
							Timestamp: time.Now(),
							Data: map[string]any{
								"identity_name":   resolved.Identity.Name,
								"identity_domain": resolved.Identity.Domain,
								"identity_upn":    resolved.Identity.UPN,
								"identity_fqdn":   resolved.Identity.String(),
								"capability":      resolved.Capability,
								"source":          resolved.Source,
								"confidence":      resolved.Confidence,
								"metadata":        resolved.Metadata,
							},
						}
						runtime.Emit(resolvedEvt)

						// Bridge resolved artifact to graph mutation.
						// Runs inline in the same goroutine to avoid
						// channel contention — no second consumer needed.
						if state != nil {
							delta := BuildDeltaFromResolved(resolved, resolvedEvt)
							if delta != nil {
								if core.ApplyDelta(state, *delta) && len(delta.NewEdges) > 0 {
									edge := delta.NewEdges[0]
									runtime.Emit(core.ServiceEvent{
										Type:      core.EvEdgeMaterialized,
										ServiceID: evt.ServiceID,
										Service:   core.ServiceResolver,
										Timestamp: time.Now(),
										Data: map[string]any{
											"source_principal": edge.SourcePrincipal,
											"target_principal": edge.TargetPrincipal,
											"access_right":     edge.AccessRight,
											"capability":       resolved.Capability,
											"provenance":       edge.Provenance,
											"confidence":       edge.Confidence,
											"edge_type":        edge.EdgeType,
										},
									})
								}
							}
						}
					}
					break // single-owner: first CanHandle match wins
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

// artifactFromEvent extracts an ArtifactEvent from a ServiceEvent.
func artifactFromEvent(evt core.ServiceEvent) *ArtifactEvent {
	artType, _ := evt.Data["artifact_type"].(string)
	if artType == "" {
		return nil
	}
	raw, _ := evt.Data["raw"].(string)
	path := extractPFXPath(raw)
	return &ArtifactEvent{
		Type:      artType,
		Stage:     "discovered",
		Path:      path,
		SourceIP:  "",
		ServiceID: evt.ServiceID,
		Timestamp: evt.Timestamp,
		Metadata:  map[string]any{"raw": raw},
	}
}

// extractPFXPath extracts the filesystem path from a cert capture line:
// "[*] Certificate written to /home/user/loot/cert_abc123.pfx"
func extractPFXPath(raw string) string {
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, ".pfx")
	if idx < 0 {
		return ""
	}
	start := idx
	for start > 0 && raw[start] != ' ' {
		start--
	}
	if start > 0 {
		start++
	}
	return strings.TrimSpace(raw[start : idx+4])
}
