# Artifact Pipeline v1 — Resolver Architecture

## Summary

Add an `internal/resolver/` package that sits between the event bus and the
edge materializer. Services emit raw artifact events (`EvArtifactDiscovered`);
asynchronous resolvers (certipy, etc.) transform those into resolved identity
events (`EvArtifactResolved`); the edge materializer creates privilege edges
from resolved identities.

ESC8 is the first resolver implementation. The pattern extends to shadow
credentials, DPAPI, kerberos tickets, and browser credentials.

## Motivation

The system currently has two data flow paths:

1. **Direct capture**: Responder/Relay capture auth material → event →
   edge (simple, synchronous, no external tooling needed)
2. **Graph ingestion**: BloodHound output → parser → converter → edges
   (batch, offline, from filesystem)

Missing: a path for **captured artifacts that need external tooling to
resolve** — e.g., a `.pfx` cert file that needs `certipy cert` to extract the
identity, or an LDAP blob that needs pyWhisker.

This gap creates coupling between services and tooling. The relay shouldn't
need to know about certipy. The resolver pattern decouples them.

## Architecture

### Package layout

```
internal/resolver/
  resolver.go           # ArtifactResolver interface, ResolvedArtifact type
  pipeline.go           # Pipeline (runtime-attached consumer)
  cert/
    resolver.go         # certResolver impl for ESC8
```

`internal/resolver/` sits alongside `internal/runtime/` and
`internal/bloodhound/`. It is importable only by `cmd/` and wired from
`modules/` via a factory pattern (like `RuntimeFactory`).

### Event taxonomy

Three new `ServiceEventType` values in `core/runtime.go`:

```go
EvArtifactDiscovered  ServiceEventType = "artifact.discovered"
EvArtifactResolved    ServiceEventType = "artifact.resolved"
EvArtifactResolveFail ServiceEventType = "artifact.resolve.failed"
```

Stages:

| Stage | Meaning | Who emits |
|-------|---------|-----------|
| `discovered` | Raw signal on stdout — file exists | Service (relay stdout) |
| `resolved` | Identity extracted, canonical form available | Resolver pipeline |
| `resolve.failed` | Resolver ran but could not extract identity | Resolver pipeline |

### ArtifactEvent struct

```go
type ArtifactEvent struct {
    Type      string         // "adcs.cert", "shadowcred.blob"
    Stage     string         // "discovered" | "captured" | "resolved"
    Path      string         // filesystem path to artifact
    SourceIP  string         // originating host
    ServiceID string         // source service
    Timestamp time.Time
    Metadata  map[string]any
}
```

### Resolver contract

```go
type ArtifactResolver interface {
    // Name returns a human-readable identifier for this resolver (e.g. "certipy").
    Name() string
    CanHandle(artifactType string) bool
    Resolve(ctx context.Context, artifact ArtifactEvent) (*ResolvedArtifact, error)
}

// Identity is a normalized representation of a resolved principal identity.
// Using a struct instead of a raw string prevents graph pollution from
// ADCS field ambiguity (UPN ≠ CN ≠ SAMAccountName).
type Identity struct {
    Name     string // sAMAccountName (e.g. "KINGSLANDING$")
    Domain   string // DNS domain (e.g. "sevenkingdoms.local")
    UPN      string // userPrincipalName if available
    CertCN   string // certificate Subject CN for traceability
}

func (id Identity) String() string {
    return id.Name + "@" + id.Domain
}

type ResolvedArtifact struct {
    Type       string            // matches artifact.Type
    Identity   Identity          // "KINGSLANDING$@sevenkingdoms.local"
    Capability string            // "CERT_AUTH"
    Source     string            // "ESC8", "SHADOW_CRED"
    Confidence float64
    Metadata   map[string]any
}
```

Resolvers return `ResolvedArtifact`, not events. The pipeline emits events from
the resolved data, keeping event emission centralized.

**Fan-out semantics:** Single-owner. The first resolver whose `CanHandle()`
returns true processes the artifact. After success or failure, the loop breaks.
No multi-resolver enrichment in v1. This keeps graph determinism and avoids
duplicate identity edges.

### Pipeline lifecycle

NOT a `ManagedService`. NOT a separate supervisor. A `Runtime`-attached
subsystem — the same pattern as the existing event consumer goroutine in
`modules/privesc.go`.

```go
// AttachResolverPipeline registers resolver pipeline on the runtime.
// It reads from runtime.Events(), dispatches to registered resolvers,
// and emits resolved identity events back to the bus.
// Runs until ctx is cancelled.
func AttachResolverPipeline(ctx context.Context, runtime core.RuntimeProvider, resolvers ...ArtifactResolver)
```

The pipeline reads from `runtime.Events()`, filters for `EvArtifactDiscovered`,
extracts an `ArtifactEvent` from the `ServiceEvent.Data` map, dispatches to
the first matching resolver, and emits `EvArtifactResolved` on success.

Mapping from `ServiceEvent.Data` → `ArtifactEvent` (the relay emits):

```
ServiceEvent.Data["artifact_type"]  → ArtifactEvent.Type
ServiceEvent.Data["raw"]            → source for ArtifactEvent.Path (extracted via regex, e.g. "certificate written to /path/cert.pfx")
ArtifactEvent.Stage                 → "discovered" (always for v1)
ArtifactEvent.SourceIP              → evt.Data["source_ip"] if set
ArtifactEvent.ServiceID             → evt.ServiceID
ArtifactEvent.Timestamp             → evt.Timestamp
```

Implementation:

```go
func AttachResolverPipeline(ctx context.Context, runtime core.RuntimeProvider, resolvers ...ArtifactResolver) {
    go func() {
        for {
            select {
            case evt, ok := <-runtime.Events():
                if !ok { return }

                if evt.Type != core.EvArtifactDiscovered { continue }

                artifact := artifactFromEvent(evt)
                if artifact == nil { continue }

                for _, r := range resolvers {
                    if !r.CanHandle(artifact.Type) { continue }
                    resolved, err := r.Resolve(ctx, *artifact)
                    if err != nil {
                        runtime.Emit(core.ServiceEvent{
                            Type:      core.EvArtifactResolveFail,
                            ServiceID: evt.ServiceID,
                            Service:   core.ServiceResolver,
                            Timestamp: time.Now(),
                            Data: map[string]any{
                                "artifact_type": artifact.Type,
                                "resolver_name": reflect.TypeOf(r).String(),
                                "error":         err.Error(),
                                "path":          artifact.Path,
                            },
                        })
                        continue
                    }
                    runtime.Emit(core.ServiceEvent{
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
                    })
                }

            case <-ctx.Done():
                return
            }
        }
    }()
}

func artifactFromEvent(evt core.ServiceEvent) *ArtifactEvent {
    artType, _ := evt.Data["artifact_type"].(string)
    if artType == "" { return nil }
    raw, _ := evt.Data["raw"].(string)
    // Extract filesystem path from raw line if present
    path := ""
    if idx := strings.Index(strings.ToLower(raw), ".pfx"); idx >= 0 {
        // Walk backwards to find start of path
        start := idx
        for start > 0 && raw[start] != ' ' {
            start--
        }
        path = strings.TrimSpace(raw[start : idx+4])
    }
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
```

### Edge materialization

The existing `materializeEdgeFromEvent` in `modules/relay_helper.go` already
dispatches on `evt.Service`. A new resolver service type
(`ServiceResolver ServiceType = "resolver"`) with `EvArtifactResolved` events
triggers a new `materializeResolverEdge`:

```go
func materializeResolverEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
    identityFQDN, _ := evt.Data["identity_fqdn"].(string)
    capability, _ := evt.Data["capability"].(string)
    confidence, _ := evt.Data["confidence"].(float64)
    if identityFQDN == "" { return nil }

    domain, _ := evt.Data["identity_domain"].(string)

    return &core.PrivilegeEdge{
        SourcePrincipal: identityFQDN,
        TargetPrincipal: "ANY_SERVICE",
        AccessRight:     capability,
        EdgeType:        "resolved_identity",
        Domain:          domain,
        Source:          evt.ServiceID,
        Confidence:      confidence,
        Weight:          2.0,
        Exploitability:  0.8,
        Noise:           0.3,
        Requires:        []string{"certipy"},
    }
}
```

## ESC8 — first resolver

### certResolver

Lives at `internal/resolver/cert/resolver.go`. Implements `ArtifactResolver`.

- `CanHandle("adcs.cert")` → true
- `Resolve(ctx, artifact)`:
  1. Runs `certipy cert -pfx <artifact.Path> -username <domain>\<user> -domain <domain> -dc-ip <dc>`
     (or briefed mode depending on what's available)
  2. Parses stdout for `Subject CN`, `UPN`, `Machine Account`
  3. Builds identity string: `CN$@DOMAIN`
  4. Returns `ResolvedArtifact{Type: "adcs.cert", Identity: ..., Capability: "CERT_AUTH", Source: "ESC8", Confidence: 0.85}`

### Relay integration (stdout detection)

In `internal/runtime/ntlmrelay.go`, add a new `isCertCaptureLine` function
separate from the existing `isCaptureLine`:

```go
// isCertCaptureLine detects ADCS certificate capture output from ntlmrelayx.
// ntlmrelayx --adcs emits lines like:
//   "[*] Certificate written to /home/user/loot/cert.pfx"
//   "[*] Saved certificate to /tmp/cert_abc123.pfx"
func isCertCaptureLine(line string) bool {
    lower := strings.ToLower(line)
    return strings.Contains(lower, "certificate") &&
        strings.Contains(lower, ".pfx")
}
```

The capture loop in `StartNTLMRelayService` emits `EvArtifactDiscovered`
for cert lines (before the existing auth-capture event emission):

```go
if isCertCaptureLine(line) {
    svc.Events <- core.ServiceEvent{
        Type:      core.EvArtifactDiscovered,
        ServiceID: svc.ID,
        Service:   core.ServiceNTLMRelay,
        Timestamp: time.Now(),
        Data: map[string]any{
            "artifact_type": "adcs.cert",
            "raw":           line,
        },
    }
}
```

This keeps the existing auth-capture path clean — cert detection is an
independent check, not a modification to `isCaptureLine`.

### Wiring in privesc.go

After services start and the event consumer goroutine is running:

```go
// Attach artifact resolver pipeline
resolvers := []resolver.ArtifactResolver{&resolver.CertResolver{}}
resolver.AttachResolverPipeline(ctx, runtime, resolvers...)
```

The existing `materializeEdgeFromEvent` dispatch handles `ServiceResolver`
events via a new case. No new consumer goroutine needed.

## What this defers (v2 candidates)

- Worker pool / throttling (single goroutine per resolver for v1)
- Multi-stage pipeline (discovered + captured are collapsed to single `discovered` for v1)
- File watcher fallback (stdout-only detection for v1)
- Artifact persistence / cache
- Plugin registration framework (resolvers are hardcoded in `privesc.go` for v1)
- Confidence decay from repeated failed resolutions

## Success criteria

1. ntlmrelayx in `--adcs` mode detects cert capture from stdout
2. `EvArtifactDiscovered` event reaches the pipeline
3. `artifactFromEvent` extracts the .pfx path from the raw line
4. `certResolver` runs certipy and extracts identity
5. `EvArtifactResolved` event emitted
6. `materializeResolverEdge` creates `CERT_AUTH` edge
7. Planner re-run shows path through VICTIM$ identity

## Non-goals

- certipy authentication using the captured cert
- Auto-login / ticket extraction
- Multi-CA failover
- Certificate storage management
- Non-ADCS artifact types (those are future resolver implementations)
