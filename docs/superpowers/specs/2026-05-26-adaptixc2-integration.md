# AdaptixC2 + Extension‑Kit Integration

- **Status:** Draft / proposal (no code yet)
- **Date:** 2026-05-26
- **Owners:** AdPack runtime + executor maintainers
- **Scope:** v0.4.0 target

## 1. Why

AdPack today is purely an **enumeration + Kerberos/NTLM tradecraft orchestrator**.
Every action is run via standalone tooling (NetExec, impacket, certipy, bloodyAD, …) over
the operator's own network position. The deliberate gap is **post‑exploitation on
implanted hosts**: there is no in‑memory execution, no agent task graph, no operator
beacon.

The user has explicitly chosen [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)
+ the official [Extension‑Kit](https://github.com/Adaptix-Framework/Extension-Kit) as the
C2 of record. **Sliver is not an option.**

This spec describes how AdPack integrates with AdaptixC2 *as an external runtime
service*, mirroring the pattern already established for Responder, Coercer, NTLM relay
and mitm6 (see `docs/superpowers/specs/2026-05-22-coercer-managed-service-design.md`).
No C2 logic is implemented inside AdPack itself; AdaptixC2 stays the source of truth
for implants, tasking and BOF execution.

## 2. AdaptixC2 surface area we rely on

Confirmed from the official docs
(<https://adaptix-framework.gitbook.io/adaptix-framework/development/teamserver-interface/web-api>)
and the v1.2 README:

| Concept | Surface | What AdPack uses it for |
|---|---|---|
| Auth | `POST /login` → JWT (`access_token`, `refresh_token`) | `adpack c2 login` once per session; tokens cached encrypted |
| Live sync | WebSocket with `Authorization: Bearer <access_token>` | Agent / cred / task event stream → AdPack state mutations |
| Agents | `GET` agents list, `POST` build, `POST` task, `POST` remove | Map agents to `core.Host`, attribute creds, dispatch BOFs |
| Credentials | `GET`, `POST` creds | Push every AdPack‑harvested cred into the Adaptix Creds Manager (single source of truth) |
| Listeners | `GET` listeners | Validate that a listener exists before requesting a payload build |
| Targets | `GET / POST` targets | Mirror AdPack's `core.State.Hosts` so the operator sees the same topology |
| Downloads / Screen | OTP channel APIs | Pull loot artifacts (ccache, mimikatz dumps) into AdPack's loot tree |

Out of scope for v0.4.0:

- Listener creation through AdPack (operators set listeners up in the GUI; AdPack only references them).
- Agent build customization beyond passing a free‑form `config` string.
- Direct WebSocket back‑pressure handling — initial impl uses long‑lived reader goroutine
  with simple reconnect, no transactional guarantees.

## 3. Extension‑Kit BOFs we depend on

The Extension‑Kit ships AxScript modules that wrap BOFs. AdPack tasks them through the
existing `Create task for the agent` endpoint (`cmdline` field), so there is no protocol
work — only the right command strings. The mapping is:

| AdPack capability | Extension‑Kit BOF group | Example `cmdline` |
|---|---|---|
| `LDAP_RECON` (post‑implant) | `AD-BOF` | `ad-bof users`, `ad-bof computers`, `ad-bof spns` |
| `KERBEROAST` (in‑memory) | `AD-BOF` | `ad-bof kerberoast` |
| `ASREP_ROAST` (in‑memory) | `AD-BOF` | `ad-bof asreproast` |
| `DCSYNC` (after privesc) | `AD-BOF` / `Creds-BOF` | `ad-bof dcsync <DC>` |
| `LATERAL_MOVEMENT` (smbexec/wmiexec/winrm) | `LateralMovement-BOF` | `lateral-bof wmi <host> <command>` |
| `PRIV_ESC` (UAC/token) | `Elevation-BOF` | `elev-bof uac-bypass`, `elev-bof token-impersonate` |
| `LSASS_DUMP`, `SAM/LSA` | `Creds-BOF` | `creds-bof lsass`, `creds-bof sam` |
| `SITUATIONAL_AWARENESS` | `SAL-BOF` / `SAR-BOF` / `Process-BOF` | `sal-bof whoami`, `proc-bof list` |
| `SHELLCODE_INJECT` | `Injection-BOF` | `inject-bof remote <pid> <sc>` |
| Persistence (registry, scheduled task, service) | `Postex-BOF` | `postex-bof scheduled-task ...` |

These exact `cmdline` strings will be locked in once we test against a live Adaptix
instance — they are the contract Extension‑Kit's AxScript exposes, not Adaptix core.

## 4. Architecture

### 4.1 Where it lives in AdPack

```text
adpack
├── core/
│   └── runtime.go                 // + ServiceAdaptix, AdaptixConfig, StartAdaptix(...) interface method
├── internal/
│   ├── runtime/
│   │   └── adaptix.go             // ManagedService wrapper + WebSocket reader goroutine
│   └── adaptix/                   // NEW pkg — pure HTTP/WS client, no orchestration logic
│       ├── client.go              // JWT login, refresh, REST verbs
│       ├── ws.go                  // WebSocket sync loop
│       ├── types.go               // Mirrors a_*, c_* response fields verbatim
│       └── client_test.go         // httptest server for the REST surface
├── modules/
│   ├── c2_sync.go                 // Pulls Adaptix state into core.State (agents, creds, targets)
│   └── c2_dispatch.go             // Translates AdPack capabilities into Adaptix task cmdlines
└── cmd/
    ├── c2.go                      // `adpack c2 login | status | sync | task | logout`
    └── ...
```

**Key invariant:** `internal/adaptix` knows nothing about AdPack types. It only speaks
the AdaptixC2 wire format. All translation happens in `modules/c2_*`.

### 4.2 Service lifecycle (mirrors Coercer/Responder pattern)

```go
// core/runtime.go (additions only)
type ServiceType string
const ServiceAdaptix ServiceType = "adaptix"

type AdaptixConfig struct {
    URL          string        // https://teamserver:4321
    Username     string
    Password     string        // never persisted in plaintext; encrypted via state cipher
    InsecureTLS  bool          // self‑signed teamserver
    SyncInterval time.Duration // fallback REST poll if WS dies
}

type RuntimeProvider interface {
    // ... existing methods ...
    StartAdaptix(ctx context.Context, cfg AdaptixConfig) (*ManagedService, error)
}
```

`internal/runtime/adaptix.go` follows the same five‑step shape as
`internal/runtime/mitm6.go`:

1. `buildCfg` validates URL, username, password.
2. `login` performs `POST /login`, stores JWT in memory only.
3. `dialWS` opens the sync WebSocket and emits `core.RuntimeEvent` items into the
   service's event channel for `agent.new`, `agent.lost`, `creds.new`, `task.completed`.
4. `Stop` cancels the context and waits for the reader goroutine.
5. Errors propagate the same way they do for Responder/Coercer (no panics, all flow
   through events).

Refresh logic uses the documented refresh endpoint; if both tokens are stale we surface
a `ServiceError` event and the supervisor restarts.

### 4.3 State integration

When the Adaptix service emits `agent.new`:

- `modules/c2_sync.go` calls `state.UpsertHost(...)` using `a_computer`, `a_internal_ip`,
  `a_domain`. The host gains a tag `c2:adaptix:<a_id>`.
- Privilege context: if `a_elevated == true`, AdPack records an
  `core.AccessRight{Type: AccessLocalAdmin, Source: a_username, Target: a_computer}`.
  This unlocks the existing local‑privilege paths in the planner *without* AdPack having
  to run NetExec to prove admin again.
- Impersonated identity (`a_impersonated`) is treated as a derived edge of type
  `Impersonates`, identical to what `s4u_delegation` produces.

When `creds.new` arrives:

- AdPack stores the credential in `core.State.Credentials` with `Source = "adaptix:<creds_id>"`.
- The reverse direction is on by default: every cred AdPack itself collects is
  pushed via `POST creds` so the operator sees a unified Creds Manager.

### 4.4 Capability dispatch

Today `modules/executor_dispatch.go` decides which *external tool* runs for each
capability. We do not change that flow. Instead we add a sibling decision point:

```go
// modules/c2_dispatch.go (sketch)
func DispatchViaAdaptix(cap core.CapabilityType, edge core.PrivilegeEdge,
                       state *core.State, c2 adaptix.Client) (Result, bool, error) {
    agent, ok := pickAgentOnHost(state, edge.SourceHost)
    if !ok {
        return Result{}, false, nil // fall back to local tool dispatch
    }
    cmdline, ok := capToBofCmdline(cap, edge)
    if !ok {
        return Result{}, false, nil
    }
    return c2.Task(agent.ID, cmdline, /*wait_answer=*/true)
}
```

The orchestrator in `modules/privesc.go` / `modules/persistence.go` calls
`DispatchViaAdaptix` first, then falls back to `dispatchTool` if no agent is available.
This means **the same capability graph drives both off‑host tooling and on‑host BOFs**.

### 4.5 Payload delivery

For initial implant placement we **don't** invent a new dropper. AdPack already has
`LATERAL_MOVEMENT` capabilities (smbexec, wmiexec, winrm, scheduled task). The new
sub‑step is:

1. Operator (or `adpack c2 build`) calls `POST agent build` with a chosen listener and
   gets a payload byte stream.
2. AdPack writes it under the loot tree as `loot/c2/<a_id>/<artifact>`.
3. Existing lateral‑movement executors copy + execute that artifact on the target,
   using the same NetExec failover ladder they use today for any other binary.

## 5. CLI surface (additions only)

```text
adpack c2 login   --url https://ts:4321 --user op --password ...
adpack c2 status                  # token validity, agent count, listeners
adpack c2 sync    [--once]        # one‑shot REST pull (if WS unavailable)
adpack c2 build   --listener http_main --agent beacon --config @cfg.json --out beacon.exe
adpack c2 task    <agent-id> "ad-bof kerberoast"
adpack c2 creds   push|pull       # bidirectional creds sync (idempotent)
adpack c2 logout
```

All credentials persist in the existing AES‑GCM SQLite state, never in a flat
config file. `adpack c2 login` is the only command that takes `--password` on the
CLI; subsequent runs reuse the encrypted blob.

The autorun pipeline gains an opt‑in flag:

```text
adpack autorun --c2 adaptix
```

When enabled, every capability that `c2_dispatch.go` can satisfy via a connected agent
takes the BOF path; everything else uses the existing tool path.

## 6. Testing strategy

1. **Unit tests for `internal/adaptix`** with `httptest.Server` covering happy paths and
   token‑refresh + 401 handling. No live teamserver needed for CI.
2. **Capability‑to‑cmdline tests** for `modules/c2_dispatch.go` — table‑driven, asserts
   that each `core.CapabilityType` produces the documented Extension‑Kit `cmdline`.
3. **Service lifecycle tests** mirror `internal/runtime/mitm6_test.go`: start/stop,
   event emission on synthetic WS frames piped through a fake dialer.
4. **End‑to‑end** against a live Adaptix instance is gated behind the existing
   `ADPACK_LIVE=1` env (same gate as other live tests). The happy path:
   `login → sync → push creds → task whoami → assert event`.

## 7. Security notes

- JWTs live only in memory; they are never written to disk. The username/password
  needed to mint them goes through the same AES‑GCM path as the rest of `core.State`.
- TLS verification is on by default. `--insecure` exists for self‑signed lab teamservers
  but logs a `RuntimeWarning` event whenever it is honoured.
- The WebSocket reader rejects any frame larger than `MaxFrameBytes` (default 4 MiB) to
  avoid an unbounded write side fanning out into AdPack state.
- Credential push to Adaptix is opt‑in (`--push-creds` on `adpack c2 sync`) so a
  defender‑side teamserver run by a different operator does not silently exfiltrate
  AdPack's harvested creds.

## 8. Out of scope (deferred to v0.5+)

- Driving listener creation / deletion from AdPack.
- Custom agent build profiles authored from inside AdPack (today we pass through
  Adaptix's `config` field opaquely).
- Multi‑teamserver fan‑out.
- Ax script / extender authoring from AdPack.

## 9. Acceptance criteria

The integration is "done for v0.4.0" when:

- `internal/adaptix` has ≥ 80 % unit‑test coverage and zero `staticcheck` findings.
- `adpack c2 login/status/task/sync/logout` all succeed against an Adaptix v1.2
  teamserver in the lab.
- An autorun against GOAD‑Light with `--c2 adaptix` and one connected beacon executes
  at least the following capabilities through Extension‑Kit BOFs instead of the local
  tool path: `LDAP_RECON`, `KERBEROAST`, `LATERAL_MOVEMENT`, `LSASS_DUMP`.
- All five pre‑commit checks (gofmt, vet, staticcheck, build, mod tidy) pass.
- The capability execution contract (`docs/superpowers/specs/2026-05-22-capability-execution-contract.md`)
  is **not** modified — Adaptix dispatch is a *backend* for existing capabilities, not
  a new contract.
