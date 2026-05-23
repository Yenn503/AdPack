# Coercer Managed Service

## Summary

Add `impacket-coercer` as a third `ManagedService` in the runtime substrate,
completing the Responder → Relay → Coercer operational loop. Coercer actively
triggers authentications from target hosts (SMB/HTTP/LDAP coercion) so that
Responder+Relay have identity material to capture. Emitted events flow through
the existing event bus → edge materialization → planner replanning pipeline.

## Design

### Event Model

Two new `ServiceEventType` values in `core/runtime.go`:

- `EvCoerceAttempt ServiceEventType = "coerce.attempt"` — coercion sent, no
  confirmation yet
- `EvCoerceSuccess ServiceEventType = "coerce.success"` — authentication
  observed, usable edge

Planner benefits from distinguishing "attempted" vs "usable" — confidence
drops for attempts, edges only form on success.

### CoercerConfig

Added to `core/runtime.go`. Follows `RelayConfig`/`ResponderConfig` pattern:

```go
type CoercerConfig struct {
    ID           string        // service ID for the supervisor
    Label        string        // human-readable label
    SourceLabel  string        // instance identifier for edge attribution
    InterfaceIP  string        // listener IP coerced targets auth against
    Targets      []string      // IPs/hostnames to coerce
    Methods      []string      // smb, http, ldap (empty = all)
    Delay        time.Duration // sleep between rounds
}
```

### RuntimeProvider Interface

Add `StartCoercer(ctx context.Context, cfg CoercerConfig) error` to
`RuntimeProvider` — same pattern as `StartRelay`/`StartResponder`. Uniform call
site in privesc.go, clear contract for modules/, easier dispatch in
`materializeEdgeFromEvent`.

### Coercer Service Implementation

`internal/runtime/coercer.go` follows the proven `NewXxx` + `StartXxx` + parsing pattern:

- **`DefaultCoercerConfig()`** — minimal sensible defaults
- **`buildCoercerArgs(cfg)`** — constructs `impacket-coercer -t TARGET -l IP -m METHOD` args
- **`startCoercer(ctx, cfg)`** — spawns `impacket-coercer` as subprocess,
  returns `(cmd, lines chan, stop func, err)`. Runs in a loop with
  `cfg.Delay` between rounds, listens for context cancellation.
- **`parseCoercerLine(line)`** — best-effort regex extractor. Tolerates:
  hostname variants (`HOST$`, `host.domain.local`, NetBIOS), missing
  timestamps, multi-method batching. Returns `(host, method, ok)`. Never
  strict — if parsing fails on a line, skip it, don't fail the round.
- **`NewCoercerService(id, label, cfg)`** — creates `ManagedService`
- **`StartCoercerService(svc, cfg, parentCtx)`** — starts goroutine that:
  1. Sets state to Running
  2. Runs coercion rounds in a loop
  3. Emits `EvCoerceAttempt` per target per round
  4. Emits `EvCoerceSuccess` when parseCoercerLine confirms auth
  5. Updates `_hash_count`-style counter in config for health summary
  6. On context cancellation: sets state to Stopped, exits loop

### Supervisor Wiring

`internal/runtime/supervisor.go` — `StartCoercer()` wrapper, same pattern as
`StartRelay`/`StartResponder`:

```go
func (s *ServiceSupervisor) StartCoercer(ctx context.Context, cfg core.CoercerConfig) error {
    // map core.CoercerConfig → runtime CoercerConfig fields
    // create service via NewCoercerService
    // register via StartService
    // start via StartCoercerService
}
```

### Edge Materialization

`modules/relay_helper.go`:

- `materializeCoercerEdge(evt)` — creates `COERCER_AUTH` edge:
  - SourcePrincipal = coerced host computer account (`HOST$`) with Domain
  - TargetPrincipal = resolved via runtime identity map if available,
    fallback = listener host IP as placeholder
  - AccessRight = `"COERCER_AUTH"`
  - Confidence: 0.8 for success, 0.4 for attempt
  - Weight: 4.0 (moderate — auth trigger precedes credential use)
  - Noise: 0.5
  - Requires: `["impacket-coercer"]`
- Add `case core.ServiceCoercion:` to `materializeEdgeFromEvent` dispatch

### Privesc Wiring

`modules/privesc.go` — explicit start order after stealth check:

```
Responder → Relay → Coercer
```

Rationale: responder seeds identity noise, relay consumes it, coercer expands
new auth surface after both are live. This improves edge diversity in early
cycles.

The existing event consumer goroutine already handles all service events via
`materializeEdgeFromEvent` — no new consumer needed.

### Success Condition

Working end-to-end in DreadGOAD-Light:

1. Coercer starts, targets a lab host
2. `EvCoerceSuccess` emitted
3. `materializeCoercerEdge` creates `COERCER_AUTH` edge
4. Planner re-run shows new path that didn't exist before
5. `runtimeHealthSummary` includes coercer state
