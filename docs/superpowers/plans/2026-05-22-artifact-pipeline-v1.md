# Artifact Pipeline v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the artifact pipeline (`internal/resolver/`) — a side-channel processing layer that transforms raw artifact events into resolved identity events. ESC8 is the first resolver implementation.

**Architecture:** `internal/resolver/` sits alongside `internal/runtime/` and `internal/bloodhound/`. The resolver pipeline is a runtime-attached consumer (not a ManagedService) that reads `EvArtifactDiscovered` events from the event bus, dispatches to registered `ArtifactResolver` implementations, and emits `EvArtifactResolved` (or `EvArtifactResolveFail`). The existing edge materializer in `modules/relay_helper.go` handles the resolved events.

**Tech Stack:** Go, `certipy` (subprocess), `core.ServiceEvent` bus, `modules/` wiring.

**Event routing:**

```
ntlmrelayx stdout
    │ [certificate written to /tmp/cert.pfx]
    ▼
EvArtifactDiscovered  ──►  AttachResolverPipeline
    │                         │
    │                    artifactFromEvent()
    │                         │
    │                    first matching ArtifactResolver
    │                         │
    │                    ┌────┴────┐
    │                    │         │
    │               success     error
    │                    │         │
    │                    ▼         ▼
    │           EvArtifact    EvArtifact
    │           Resolved      ResolveFail
    │                    │         │
    └────────────────────┼─────────┘
                        ▼
              materializeEdgeFromEvent
                        │
                    [new CERT_AUTH edge]
                        │
                    planner re-run
```

**Resolver semantics:** Single-owner — first resolver whose `CanHandle()` returns true processes the artifact. After success or failure, the loop breaks. No multi-resolver fan-out in v1.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `core/runtime.go` | Modify | Add `EvArtifactDiscovered`, `EvArtifactResolved`, `EvArtifactResolveFail` event types; `ServiceResolver` type |
| `internal/resolver/resolver.go` | Create | `ArtifactResolver` interface, `Identity` struct, `ResolvedArtifact` struct, `ArtifactEvent` struct |
| `internal/resolver/pipeline.go` | Create | `AttachResolverPipeline(ctx, runtime, resolvers...)` — event consumer that dispatches to resolvers |
| `internal/resolver/cert/resolver.go` | Create | `certResolver` implementing `ArtifactResolver` — runs certipy parse, extracts identity |
| `internal/runtime/ntlmrelay.go` | Modify | Add `isCertCaptureLine()`, emit `EvArtifactDiscovered` for cert captures |
| `modules/relay_helper.go` | Modify | Add `materializeResolverEdge`, add `ServiceResolver` dispatch case |
| `modules/privesc.go` | Modify | Wire resolver pipeline after services start |
| `internal/resolver/pipeline_test.go` | Create | Tests for pipeline dispatch, error handling, event emission |
| `internal/resolver/cert/resolver_test.go` | Create | Tests for certResolver parsing |

---

### Task 1: Core types — event types + service type

**Files:**
- Modify: `core/runtime.go`

- [ ] **Step 1: Add event types**

After existing event type consts, add:

```go
EvArtifactDiscovered  ServiceEventType = "artifact.discovered"
EvArtifactResolved    ServiceEventType = "artifact.resolved"
EvArtifactResolveFail ServiceEventType = "artifact.resolve.failed"
```

- [ ] **Step 2: Add ServiceResolver type**

After `ServiceHTTPRelay ServiceType = "http_relay"` in the ServiceType block, add:

```go
ServiceResolver ServiceType = "resolver"
```

- [ ] **Step 3: Verify compile**

```bash
go build ./core/... && go vet ./core/...
```

Expected: clean

- [ ] **Step 4: Commit**

```bash
git add core/runtime.go
git commit -m "feat: add artifact pipeline event types (discovered/resolved/fail) + ServiceResolver"
```

---

### Task 2: Resolver package — interface + types

**Files:**
- Create: `internal/resolver/resolver.go`

- [ ] **Step 1: Write the file**

```go
package resolver

import "context"

// ArtifactEvent describes a raw artifact discovered by a runtime service.
// At the "discovered" stage, the path may be inferred from stdout and
// is not guaranteed to exist yet.
type ArtifactEvent struct {
    Type      string            // "adcs.cert", "shadowcred.blob"
    Stage     string            // "discovered" (only stage in v1)
    Path      string            // filesystem path to artifact
    SourceIP  string            // originating host
    ServiceID string            // source service (e.g. "ntlmrelayx-main")
    Timestamp time.Time
    Metadata  map[string]any
}

// Identity is a normalized representation of a resolved principal.
type Identity struct {
    Name     string // sAMAccountName (e.g. "KINGSLANDING$")
    Domain   string // DNS domain (e.g. "sevenkingdoms.local")
    UPN      string // userPrincipalName if available
    CertCN   string // certificate Subject CN for traceability
}

func (id Identity) String() string { return id.Name + "@" + id.Domain }

// ResolvedArtifact is the output of an ArtifactResolver.
type ResolvedArtifact struct {
    Type       string   // matches artifact.Type
    Identity   Identity // normalized principal identity
    Capability string   // "CERT_AUTH", "SHADOW_CRED", etc.
    Source     string   // "ESC8", "SHADOW_CRED", etc.
    Confidence float64
    Metadata   map[string]any
}

// ArtifactResolver can resolve a specific artifact type into an identity.
type ArtifactResolver interface {
    Name() string
    CanHandle(artifactType string) bool
    Resolve(ctx context.Context, artifact ArtifactEvent) (*ResolvedArtifact, error)
}
```

The struct includes `Timestamp` for traceability — include `"time"` in imports.

- [ ] **Step 2: Verify compile**

```bash
go build ./internal/resolver/... && go vet ./internal/resolver/...
```

Expected: clean

- [ ] **Step 3: Commit**

```bash
git add internal/resolver/resolver.go
git commit -m "feat: add resolver package types + ArtifactResolver interface"
```

---

### Task 3: Resolver pipeline — event consumer

**Files:**
- Create: `internal/resolver/pipeline.go`
- Create: `internal/resolver/pipeline_test.go`

- [ ] **Step 1: Write pipeline.go**

```go
package resolver

import (
    "context"
    "strings"
    "time"

    "adpack/core"
)

// AttachResolverPipeline registers the artifact resolution pipeline on
// the runtime. It reads EvArtifactDiscovered events, dispatches to
// registered resolvers, and emits EvArtifactResolved or
// EvArtifactResolveFail. Runs until ctx is cancelled.
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
                                "resolver_name": r.Name(),
                                "error":         err.Error(),
                                "path":          artifact.Path,
                            },
                        })
                    } else {
                        runtime.Emit(core.ServiceEvent{
                            Type:      core.EvArtifactResolved,
                            ServiceID: evt.ServiceID,
                            Service:   core.ServiceResolver,
                            Timestamp: time.Now(),
                            Data: map[string]any{
                                "identity_name":   resolved.Identity.Name,
                                "identity_domain": resolved.Identity.Domain,
                                "identity_upn":    resolved.Identity.UPN,
                                "capability":      resolved.Capability,
                                "source":          resolved.Source,
                                "confidence":      resolved.Confidence,
                                "metadata":        resolved.Metadata,
                            },
                        })
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
// Returns nil if the event doesn't carry artifact metadata.
func artifactFromEvent(evt core.ServiceEvent) *ArtifactEvent {
    artType, _ := evt.Data["artifact_type"].(string)
    if artType == "" { return nil }
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
    if idx < 0 { return "" }
    start := idx
    for start > 0 && raw[start] != ' ' {
        start--
    }
    if start > 0 { start++ } // skip the space
    return strings.TrimSpace(raw[start : idx+4])
}
```

- [ ] **Step 2: Write pipeline_test.go**

Test `extractPFXPath`:
- `TestExtractPFXPath_Normal` — `"[*] Certificate written to /tmp/cert.pfx"` → `"/tmp/cert.pfx"`
- `TestExtractPFXPath_NoMatch` — `"relayed session from USER"` → `""`
- `TestExtractPFXPath_Empty` — `""` → `""`

Test `artifactFromEvent`:
- `TestArtifactFromEvent_Valid` — event with artifact_type and raw → ArtifactEvent with extracted path
- `TestArtifactFromEvent_MissingType` → nil

Test the pipeline with a mock resolver using a real supervisor instance (same pattern as existing supervisor tests):

```go
type mockResolver struct {
    name      string
    canHandle bool
    resolve   func(ctx context.Context, artifact ArtifactEvent) (*ResolvedArtifact, error)
}

func (m *mockResolver) Name() string { return m.name }
func (m *mockResolver) CanHandle(t string) bool { return m.canHandle }
func (m *mockResolver) Resolve(ctx context.Context, a ArtifactEvent) (*ResolvedArtifact, error) {
    return m.resolve(ctx, a)
}

func TestAttachResolverPipeline_Dispatch(t *testing.T) {
    supervisor := NewSupervisor() // from internal/runtime
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    handled := make(chan bool, 1)
    resolvers := []ArtifactResolver{&mockResolver{
        canHandle: true,
        resolve: func(ctx context.Context, a ArtifactEvent) (*ResolvedArtifact, error) {
            handled <- true
            return &ResolvedArtifact{
                Type: a.Type,
                Identity: Identity{Name: "KINGSLANDING$", Domain: "sevenkingdoms.local"},
                Capability: "CERT_AUTH",
                Source: "ESC8",
                Confidence: 0.85,
            }, nil
        },
    }}

    AttachResolverPipeline(ctx, supervisor, resolvers...)
    supervisor.Emit(core.ServiceEvent{
        Type: core.EvArtifactDiscovered,
        ServiceID: "ntlmrelayx-main",
        Service: core.ServiceNTLMRelay,
        Timestamp: time.Now(),
        Data: map[string]any{"artifact_type": "adcs.cert", "raw": "certificate written to /tmp/cert.pfx"},
    })

    select {
    case <-handled:
    case <-time.After(time.Second):
        t.Fatal("resolver was not called")
    }
}
```

Add `TestAttachResolverPipeline_Error` — mock resolver returns error → `EvArtifactResolveFail` emitted. Verify by observing events via `supervisor.Events()`.
Add `TestAttachResolverPipeline_WrongEventType` — emit non-artifact event → no handler called.

- [ ] **Step 3: Verify compile and tests**

```bash
go build ./internal/resolver/... && go vet ./internal/resolver/...
go test ./internal/resolver/... -v -count=1
```

Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add internal/resolver/pipeline.go internal/resolver/pipeline_test.go
git commit -m "feat: add resolver pipeline with event dispatch + failure handling"
```

---

### Task 4: certResolver — ESC8 identity extraction

**Files:**
- Create: `internal/resolver/cert/resolver.go`
- Create: `internal/resolver/cert/resolver_test.go`

- [ ] **Step 1: Write resolver.go**

```go
package cert

import (
    "context"
    "fmt"
    "os/exec"
    "regexp"
    "strings"

    "adpack/internal/resolver"
)

type CertResolver struct{}

func (r *CertResolver) CanHandle(artifactType string) bool {
    return artifactType == "adcs.cert"
}

// certipyCertOutputRe extracts identity fields from certipy cert output.
// "Subject CN=KINGSLANDING.sevenkingdoms.local"
// "UPN=HOST$@sevenkingdoms.local"
// "Machine Account: KINGSLANDING$"
var certipySubjectCN = regexp.MustCompile(`Subject\s+CN=([^\s,]+)`)
var certipyUPN = regexp.MustCompile(`UPN=(\S+@\S+)`)
var certipyMachineAccount = regexp.MustCompile(`(?:Machine\s+)?Account[:\s]+(\S+\$)`)

func (r *CertResolver) Resolve(ctx context.Context, artifact resolver.ArtifactEvent) (*resolver.ResolvedArtifact, error) {
    if artifact.Path == "" {
        return nil, nil
    }

    if artifact.Path == "" {
        return nil, fmt.Errorf("cert resolver: empty artifact path")
    }

    cmd := exec.CommandContext(ctx, "certipy", "cert", "-pfx", artifact.Path)
    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("certipy cert failed: %w", err)
    }

    outStr := string(output)
    ident := resolver.Identity{}

    if m := certipyMachineAccount.FindStringSubmatch(outStr); len(m) >= 2 {
        ident.Name = strings.TrimSpace(m[1])
    }
    if m := certipyUPN.FindStringSubmatch(outStr); len(m) >= 2 {
        ident.UPN = strings.TrimSpace(m[1])
        if parts := strings.SplitN(ident.UPN, "@", 2); len(parts) == 2 && ident.Name == "" {
            ident.Name = parts[0]
            ident.Domain = parts[1]
        }
    }
    if m := certipySubjectCN.FindStringSubmatch(outStr); len(m) >= 2 {
        ident.CertCN = strings.TrimSpace(m[1])
    }
    if ident.Domain == "" {
        if parts := strings.SplitN(ident.CertCN, ".", 2); len(parts) == 2 {
            ident.Domain = parts[1]
        }
    }
    if ident.Name == "" || ident.Domain == "" {
        return nil, fmt.Errorf("cert resolver: could not extract identity from cert (name=%q domain=%q)", ident.Name, ident.Domain)
    }

    return &resolver.ResolvedArtifact{
        Type:       artifact.Type,
        Identity:   ident,
        Capability: "CERT_AUTH",
        Source:     "ESC8",
        Confidence: 0.85,
        Metadata: map[string]any{
            "cert_path": artifact.Path,
        },
    }, nil
}
```

- [ ] **Step 2: Write resolver_test.go**

Test the regex patterns against sample certipy output. These are parser-level tests that don't require an actual certipy binary:

```go
func TestCertipyRegex_MachineAccount(t *testing.T) {
    out := `Subject CN=KINGSLANDING.sevenkingdoms.local
UPN=HOST$@sevenkingdoms.local
Machine Account: KINGSLANDING$`
    m := certipyMachineAccount.FindStringSubmatch(out)
    if len(m) < 2 || m[1] != "KINGSLANDING$" { t.Fatal("expected KINGSLANDING$") }
}

func TestCertipyRegex_UPN(t *testing.T) {
    out := `UPN=HOST$@sevenkingdoms.local`
    m := certipyUPN.FindStringSubmatch(out)
    if len(m) < 2 || m[1] != "HOST$@sevenkingdoms.local" { t.Fatal("expected UPN match") }
}

func TestCertipyRegex_SubjectCN(t *testing.T) {
    out := `Subject CN=KINGSLANDING.sevenkingdoms.local`
    m := certipySubjectCN.FindStringSubmatch(out)
    if len(m) < 2 || m[1] != "KINGSLANDING.sevenkingdoms.local" { t.Fatal("expected CN match") }
}
```

- [ ] **Step 3: Verify compile and tests**

```bash
go build ./internal/resolver/... && go vet ./internal/resolver/...
go test ./internal/resolver/... -v -count=1
```

Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add internal/resolver/cert/
git commit -m "feat: add certResolver for ESC8 identity extraction"
```

---

### Task 5: Relay integration — cert capture detection

**Files:**
- Modify: `internal/runtime/ntlmrelay.go`

- [ ] **Step 1: Read existing file**

Read the `isCaptureLine` function and the `StartNTLMRelayService` function to identify insertion points.

- [ ] **Step 2: Add isCertCaptureLine**

Add after `isCaptureLine`:

```go
func isCertCaptureLine(line string) bool {
    lower := strings.ToLower(line)
    return strings.Contains(lower, "certificate") &&
        strings.Contains(lower, ".pfx")
}
```

- [ ] **Step 3: Add artifact emission in StartNTLMRelayService capture loop**

In the existing capture goroutine (line ~191), after the existing auth-capture event emission and before the hash event emission, add:

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

- [ ] **Step 4: Verify compile and tests**

```bash
go build ./internal/runtime/... && go vet ./internal/runtime/...
go test ./internal/runtime/... -count=1
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/ntlmrelay.go
git commit -m "feat: relay emits EvArtifactDiscovered for cert capture lines"
```

---

### Task 6: Edge materialization + privesc wiring

**Files:**
- Modify: `modules/relay_helper.go`
- Modify: `modules/privesc.go`

- [ ] **Step 1: Add materializeResolverEdge**

In `relay_helper.go`, after `materializeCoercerEdge`, add:

```go
func materializeResolverEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
    identityFQDN, _ := evt.Data["identity_fqdn"].(string)
    capability, _ := evt.Data["capability"].(string)
    confidence, _ := evt.Data["confidence"].(float64)
    if identityFQDN == "" { return nil }

    return &core.PrivilegeEdge{
        SourcePrincipal: identityFQDN,
        TargetPrincipal: "ANY_SERVICE",
        AccessRight:     capability,
        EdgeType:        "resolved_identity",
        Domain:          domain,
        Source:          evt.ServiceID, // traceable to originating service
        Confidence:      confidence,
        Weight:          2.0,
        Exploitability:  0.8,
        Noise:           0.3,
        Requires:        []string{"certipy"},
    }
}
```

- [ ] **Step 2: Add dispatch case**

In `materializeEdgeFromEvent`, after `case core.ServiceCoercion:`, add:

```go
case core.ServiceResolver:
    return materializeResolverEdge(evt)
```

- [ ] **Step 3: Wire resolver pipeline in privesc.go**

In `modules/privesc.go`, add imports to existing import block:

```go
import (
    // ... existing imports ...
    "adpack/internal/resolver"
    "adpack/internal/resolver/cert"
)
```

After the event consumer goroutine (after `}()` closing the go func), add:

```go
// Attach artifact resolver pipeline (certipy → identity extraction)
resolvers := []resolver.ArtifactResolver{&cert.CertResolver{}}
resolver.AttachResolverPipeline(ctx, runtime, resolvers...)
```

- [ ] **Step 4: Verify compile**

```bash
go build ./modules/... && go vet ./modules/...
```

Expected: clean

- [ ] **Step 5: Commit**

```bash
git add modules/relay_helper.go modules/privesc.go
git commit -m "feat: add resolver edge materialization + privesc wiring"
```

---

### Task 7: Tests + final verification

- [ ] **Step 1: Full test suite**

```bash
go test ./... -count=1
```

Expected: all pass

- [ ] **Step 2: go vet**

```bash
go vet ./...
```

Expected: clean

- [ ] **Step 3: go build**

```bash
go build ./...
```

Expected: clean

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: finalize artifact pipeline v1"
```
