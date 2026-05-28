# Offensive Closure Layer

**Date**: 2026-05-26
**Status**: Draft
**Phase**: Stage 1 — Tactical Loop Closure

## Overview

The framework currently enumerates AD environments comprehensively but fails to
materialize privilege escalation paths into actual compromise. This spec defines
the offensive closure layer that turns graph knowledge into credential-to-DA
transformation loops.

## Architecture Layers

```
Layer 1: Runtime (always-on)
  state store · event bus · crack workers · planner core

Layer 2: Intelligence
  planner (Dijkstra) · fixpoint engine · path scoring

Layer 3: Execution (phases)
  discovery · enumeration · privesc · persistence
```

The cracking pipeline belongs in Layer 1. Exploitation recursion lives in
Layer 3 (Stage 1), migrating to Layer 2 (Stage 3).

**Convergence ownership migration**:
- Stage 1: `privesc.go` is the **local convergence controller** (bounded loop
  scoped to credential materialization)
- Stage 3: fixpoint engine becomes the **global convergence authority**
  (continuous, event-driven)
- This prevents an architectural contradiction where privesc.go competes with
  the fixpoint engine for convergence ownership

## Stage 1 Scope: Tactical Loop Closure

### 1. Phase Status Fix

**Problem**: `cmd/autorun.go` sets `PhaseSkipped` when `--skip-fail` is active
and a phase fails. Status display shows `⊘ skipped` for genuinely failed phases.

**Fix**:
- `Failed` = attempted, outcome negative
- `Skipped` = not eligible now (missing prerequisites)
- `Skipped` always carries a reason code (e.g. `NO_CREDS`, `NO_SESSION`,
  `NO_DCSYNC_RIGHTS`, `NO_SYSTEM_CONTEXT`, `NO_PATH`)
- `PhaseBlocked` (future) = system cannot run yet (environmental limitation)
- Skipped phases only re-evaluated on matching event triggers — never via
  global retry loops

**Files**: `cmd/autorun.go` (phase status save), `tui/model.go` (status display)

### 2. Kerberoast / AS-REP Hash Capture

**Problem**: `executor_dispatch.go` runs `impacket-GetUserSPNs -request` and
`impacket-GetNPUsers` but never parses the `$krb5tgs$` / `$krb5asrep$` hashes
from stdout.

**Fix**:
- Add tool-specific output parsers in `executor_dispatch.go`:
  - `ParseKerberoastOutput(stdout) → []HashCred`
  - `ParseASREPOutput(stdout) → []HashCred`
- Store parsed hashes as `core.Credential{Type: CredHash, Hash: hash}` in
  `ToolResult.Creds`
- Credentials flow naturally through `ExecuteAndReconcile → ApplyDelta →
  state.Creds`
- Structured metadata per credential: `SourceTool`, `TargetAccount`, `Domain`,
  `Confidence`

**Regex patterns** (with unit tests):
- `$krb5tgs$23$*` (Kerberoast TGS)
- `$krb5asrep$23$*` (AS-REP roast)
- NTLM `aad3b435...` (secretsdump)
- Mixed stdout noise, partial lines, multi-line concatenation, duplicates

**Files**: `modules/executor_dispatch.go`, `core/state.go` (Credential metadata)

### 3. Cracking Pipeline

**Architecture** (root-level lifecycle, Layer 1):
```
executor → extract hash → event bus → HashQueue → CrackWorker
  → CredentialMaterializer → state → planner interrupt
```

**Components**:

- **`HashQueue`**: thread-safe, dedup by hash value, priority tiers, max queue
  depth, per-type rate limits, dedup TTL window
- **`CrackWorker`**: background goroutine, launches hashcat per hash type,
  polls `--show` every N seconds, tracks job metadata + potfile
- **`CredentialMaterializer`**: listens for cracked creds, validates via
  SMB/LDAP, inserts into state, emits `CredentialAdded` event
- **Crack ambiguity handling**: The materializer enforces:
  - **Hash dedup**: identical hash values (same type) → single entry
  - **Identity dedup**: same `user@domain` → merge cracked password into
    existing entry rather than duplicate
  - **Confidence merging rule**: when two sources produce the same credential,
    take the highest confidence; if one is validated and one is not, keep the
    validated version
  - These prevent duplicate DA creds from causing repeated planner interrupts
- **`PlannerInterrupt`**: on high-value cred, triggers re-evaluation of
  validation + privesc + planner

**Priority tiers**: DA accounts > SPNs > service accounts > users with sessions
> BH path principals

**Backpressure**: max queue depth, per-type rate limits, dedup TTL window

**Integration**: spawned in `cmd/root.go`, communicates via `CrackEventBus` Go
channel (not a separate pub/sub abstraction — Stage 1 uses a simple channel for
determinism). The privesc recursion loop checks this channel for new materialized
creds. Stage 2 will formalize this into a full event bus.

**New files**: `internal/cracker/` package with `queue.go`, `worker.go`,
`materializer.go`

### 4. ADCS Exploitation Executor

**Model**: capability family with sub-strategies (not one capability per ESC
type).

**Stage A — Certificate Enrollment** (`ADCS_CERT_ENROLL`):
- `certipy-request -u USER@DOMAIN -p PASS -ca CA -template VULN_TEMPLATE
  -upn DA_USER@DOMAIN`
- Returns enrollment success/failure + .pfx cert

**Stage B — Authentication Materialization** (`ADCS_PKINIT_AUTH`):
- `certipy-auth -pfx cert.pfx -domain DOMAIN -dc-ip DC`
- PKINIT → TGT → credential validation
- Stores DA credential on success

**Executor pattern** (matching DCSync/RBCD/S4U):
- `internal/executorbackend/adcs_esc1/executor.go`
- `Capability(): "ADCS_CERT_ENROLL" / "ADCS_PKINIT_AUTH"`
- `CanExecute()`: certipy exists, enrollee has enrollment rights (edge
  precondition), target identity resolvable
- **Template vulnerability is NOT re-validated in `CanExecute()`** — it is
  pre-computed by `compute_edges()` (the graph analysis step in the recursion
  loop, which runs ADCS template detection). The executor receives the
  vulnerable template name as edge metadata. This avoids duplicate template
  parsing logic.
- **Staleness guard**: Despite the above, `CanExecute()` MUST include a
  staleness check on the edge. ADCS state can change during runtime (lab
  resets, multi-node race conditions). Use `edge.ObservedAt` with a configurable
  TTL (default 5 minutes). If the edge is older than TTL, `CanExecute()` returns
  false, forcing a re-evaluation on the next iteration.
- `Execute()`: runs certipy tools, returns `ExecutionResult` with
  `ValidCredential` edge + DA credential

**Registration**:
- `core/capability.go`: add `ADCS_CERT_ENROLL`, `ADCS_PKINIT_AUTH` to
  `AccessRightToCapability`
- `cmd/root.go`: register executor in `NewCapabilityRegistry()`

**Sub-strategies**: ESC1, ESC13 (shared base executor, strategy switch)

**Files**:
- `internal/executorbackend/adcs/` (new, strategy-based)
- `core/capability.go` (registry entries)
- `modules/executor_dispatch.go` (dispatch cases)
- `modules/reconcile.go` (verification)

### 5. Bounded Recursion in privesc.go

The convergence authority for Stage 1. NOT a global retry loop — scoped to
credential materialization through the capability executor graph.

```
for i < maxIterations (default 5):
  compute_edges()          // ADCS templates, delegation, BH graph
  score_paths()            // Dijkstra over edge graph
  execute_best_paths()     // materialize edges, produce creds
  if state_delta_detected(new_creds ∨ new_edges ∨ path_score_improvement):
    validate(new_creds)
    if DA_validated:
      break                // goal achieved
    i++
    continue               // rerun with expanded identity set
  else:
    break                  // converged
```

**Termination**:
- No state delta → converged
- DA credential validated → goal achieved
- Max iterations (5) → safety valve
- All remaining paths blocked → exhausted

**Delta classification**: each iteration classifies the state delta before
deciding to continue:
- `DELTA_CREDENTIAL` — new credential materialized (highest value)
- `DELTA_EDGE` — new high-value edge discovered (delegation, RBCD, ESC1
  enrollment)
- `DELTA_PATH` — path to DA shortened (fewer steps, lower cost)
- `DELTA_NOISE` — churn with no exploitable change (do NOT trigger re-run)

Only `DELTA_CREDENTIAL`, `DELTA_EDGE`, and `DELTA_PATH` trigger a new
iteration. `DELTA_NOISE` converges immediately. This prevents low-value churn
(credential re-discovery, stale edge re-validation) from causing infinite
loops.

**Convergence signals**:
```json
{
  "iteration_id": 2,
  "creds_added": ["north.sevenkingdoms.local\\krbtgt"],
  "edges_added": 47,
  "score_delta": -3.2,
  "best_path_before": "samwell → brandon → ... → DA (8 steps)",
  "best_path_after": "samwell → krbtgt → DA (2 steps)",
  "termination_signal": "da_validated"
}
```

**Control flow**:
1. `compute_edges()` — runs the full privesc detection pipeline (ADCS
   templates, delegation, BH graph, ACL) and merges new edges into state
2. `score_paths()` — calls `planner.PlanPaths()` (Dijkstra over edge graph)
3. `execute_best_paths()` — calls `ExecuteBestPaths()` → `ExecuteAndReconcile()`
   → `AccessRightToCapability()` → capability registry → executor dispatch

The loop NEVER dispatches executors directly. It always goes through the
capability registry. This prevents recursion from bypassing the executor
abstraction layer, which would cause state desync between the fixpoint engine
and the real executor graph.

**Enforcement**: Add a guard in `dispatchTool()` (or the executor factory) that
panics or logs a fatal error if an executor is invoked outside the capability
registry path. This prevents silent bypasses during development — the
registry is the single point of executor dispatch for the entire framework.

**Files**: `modules/privesc.go`

## Event Model (Stage 2 Foundation)

Implemented in Stage 1 as internal channels, formalized in Stage 2:

| Event | Trigger | Consumer |
|-------|---------|----------|
| `HashDiscovered` | Hash extraction | HashQueue |
| `CredentialCracked` | CrackWorker | CredentialMaterializer |
| `CredentialValidated` | Validation phase | PlannerInterrupt |
| `EdgeUnlocked` | New high-value edge discovered | Recursion loop |
| `PathImproved` | DA path shortened (fewer steps, lower cost) | Recursion loop |

## Implementation Order

1. Phase status fix (`cmd/autorun.go`)
2. Hash capture parsers + tests (`modules/executor_dispatch.go`)
3. Hash regex unit tests
4. Cracking pipeline infrastructure (`internal/cracker/`)
5. ADCS executor family (`internal/executorbackend/adcs/`)
6. Bounded recursion in privesc.go
7. Integration test against GOAD-Light

## Non-Goals (Stage 1)

- Trust-aware parent/child pivoting → Stage 2
- Session-to-token exploitation → Stage 2
- Goal-directed replanning (targeting specific BH steps) → Stage 2
- Full fixpoint convergence authority migration → Stage 3
- Event-driven architecture formalization → Stage 2
