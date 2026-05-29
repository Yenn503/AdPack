# AdPack — Agent Guide

## Project Overview

AdPack is a state-aware Active Directory attack orchestration tool written in Go. It chains 14 attack phases with automatic state tracking, privilege escalation path planning, and credential management.

Repository: `https://github.com/Yenn503/AdPack`

## State Machine

`ADState` (`core/state.go:319`) tracks hosts, users, credentials, sessions, privilege edges, and phase progress. All stored in SQLite with AES-256-GCM encryption (`storage/db.go`). Key fields:

- `Hosts` — discovered machines with OS, EDR, ports
- `Users` / `Groups` / `Computers` — AD objects
- `Creds` — plaintext, NTLM hash, ticket, cert, token
- `Sessions` — user logon sessions on hosts
- `Edges` — directed privilege relationships (PrivilegeEdge)
- `Phases` — map of Phase -> PhaseStatus (untouched/in_progress/complete/skipped/failed)
- `Runtime` — active services (ntlmrelayx, Responder, Coercer, mitm6)
- `Tokens` — OAuth access/refresh tokens from cloud auth
- `CloudResources` — discovered Entra ID resources

View current state: `adpack status`. Gaps are detected by `ADState.DetectGaps()` (`core/state.go:347`).

## Phases and DAG

14 phases with dependency ordering defined in `Phase.Dependencies()` (`core/state.go:275`):

```
initial_access -> discovery -> enumeration -> credential_acq -> session_harvest -> graph_analysis
                                                                                         |
                                                                                         v
                                                                                 validation
                                                                                         |
                                                                                         v
                                                                          privesc -> credential_acq (re-run) -> lateral -> persistence

initial_access -> cloud_enum -> cloud_cred_acq -> cloud_privesc -> cloud_pillage
```

Cloud phases fork from initial_access and run in parallel with on-prem phases. Phase execution order is determined dynamically by `ADState.NextPhase()` which checks dependency completion, credential status, and fast-tracks to lateral/persistence when DA creds are held.

### New Phase Descriptions

| Phase | Description |
|-------|-------------|
| `initial_access` | Teams phishing, device code auth, OAuth consent phishing. Gets the first foothold. |
| `cloud_enum` | Enumerate Entra ID tenant (users, groups, apps, CAPs) |
| `cloud_cred_acq` | Cloud credential acquisition (O365 password spray) |
| `cloud_privesc` | Cloud privilege escalation analysis (Global Admin, Azure roles) |
| `cloud_pillage` | Search/export mail, SharePoint, OneDrive, Teams via Graph API |

## Key Commands

| Command | Description | File |
|---------|-------------|------|
| `adpack autorun` | Full automated attack chain | `cmd/autorun.go` |
| `adpack run <phase>` | Execute a single phase | `cmd/run.go` |
| `adpack status` | Current state and gaps | `cmd/status.go` |
| `adpack next` | Recommended next phase | `cmd/next.go` |
| `adpack init` | Initialize engagement | `cmd/init.go` |
| `adpack cred` | Credential inventory (list/export/status/verify) | `cmd/cred.go` |
| `adpack validate` | Validate tools/config/setup | `cmd/validate.go` |
| `adpack bloodhound` | BloodHound collection | `cmd/bloodhound.go` |
| `adpack phases` | List available phases | `cmd/reset.go` |
| `adpack profiles` | List evasion profiles | `cmd/reset.go` |
| `adpack interactive` | TUI dashboard | `cmd/interactive.go` |
| `adpack session` | Engagement session management | `cmd/session.go` |
| `adpack query [--preset <name>] [--list-presets]` | BloodHound Cypher queries with preset library | `cmd/query.go` |
| `adpack report` | Engagement reports (html/md/json) | `cmd/report.go` |
| `adpack ingest` | Import tool output | `cmd/ingest.go` |
| `adpack initial teams` | Teams phishing via TeamsPhisher | `cmd/initial.go` |
| `adpack initial device-code` | Device code auth for Entra ID token | `cmd/initial.go` |
| `adpack initial consent-phish` | OAuth consent phishing via GraphRunner | `cmd/initial.go` |
| `adpack cloud enum` | Enumerate Entra ID tenant | `cmd/cloud.go` |
| `adpack cloud cred-acq` | O365 password spray | `cmd/cloud.go` |
| `adpack cloud privesc` | Cloud privilege escalation analysis | `cmd/cloud.go` |
| `adpack cloud pillage` | Search/export mail, SharePoint, Teams | `cmd/cloud.go` |

Sub-commands for ADCS, Kerberos, DPAPI, GPO, LAPS, gMSA, NTLM coercion, Zerologon, NoPac, shadow copy, domain trusts, initial access, cloud attacks, and more — see `README.md` for full table.

## Tools

External tools wrapped by AdPack for attack execution:

| Tool | Type | File | Purpose |
|------|------|------|---------|
| NetExec (nxc) | CLI | `tools/netexec.go` | SMB/WinRM/WMI/MSSQL enumeration and execution |
| roadrecon/roadtx | CLI | `tools/azure.go` | Entra ID reconnaissance and token manipulation |
| TeamsPhisher | Python3 | `tools/teams.go` | Teams phishing |
| TokenTactics | PowerShell | `tools/tokentactics.go` | Entra ID token manipulation |
| GraphRunner | PowerShell | `tools/graphrunner.go` | Graph API post-exploitation |
| AADInternals | PowerShell | `tools/aadinternals.go` | Deep Entra ID internals |
| nanodump | CLI | `tools/nanodump.go` | LSASS minidump |
| go-mimikatz | CLI | `tools/gomimikatz.go` | Mimikatz functionality (Go port) |
| MiniPlasma | CLI | `tools/miniplasma.go` | LSASS protection bypass |
| PPLShade | CLI | `tools/pplshade.go` | BYOVD PPL bypass |
| PhantomKiller | CLI | `tools/phantomkiller.go` | BYOVD EDR process killer |
| ldapsearch | CLI | `tools/ldapsearch.go` | LDAP directory search |
| deploy | utility | `tools/deploy.go` | Payload deployment helpers |

## Evasion Profiles

Three profiles for credential acquisition, configured via `profile` in `adpack.yaml`:

| Profile | Mechanism | Use Case |
|---------|-----------|----------|
| `native` | reg add + sc stop + taskkill, then nanodump | Default — kills Defender, no extra binaries |
| `pplshade` | BYOVD PPL bypass via PPLShade + LECOMAx64.sys | LSASS is PPL-protected |
| `phantomkiller` | BYOVD EDR process killer via PhantomKiller + PhantomKiller.sys | Need to kill EDR processes |

Evasion history per host tracked in `Host.EvasionHist` field (JSON list of profiles attempted).

## Configuration

Config file: `adpack.yaml` in project root or `~/.adpack/config.yaml`. Full reference in `config.example.yaml`.

Key config sections:
- `domain` — target AD domain
- `profile` — evasion profile (native/pplshade/phantomkiller)
- `seeds` — bootstrapping credentials (user + password/hash per domain)
- `cracking` — hashcat path, wordlist, rules, timeout
- `scope` — CIDR whitelist for attack targets (safety net)
- `db_path` — SQLite path (default: `~/.adpack/state.db`)
- `proxy_address` — SOCKS5 proxy for C2 routing
- `viper` — Neo4j connection for BloodHound graph queries
- `timing` — delay_ms, jitter, max_concurrent

Credentials encrypted with AES-256-GCM in SQLite. Key file stored alongside database.
Config can also be set via `ADPACK_PROXY` environment variable.

## Constraints

1. **No hardcoded IPs/domains in code** — all user-configurable via `adpack.yaml`, CLI flags, or state DB
2. **`adpack.yaml` is gitignored** — never commit local config; commit `config.example.yaml` for reference
3. **Existing test suite must pass before any commit** — run `go test ./...` (or `make test`)
4. **Must use `go build -o adpack .` after changes** — or `make build`

## Design Principles

1. **AdPack is a smart orchestrator, not a monolithic framework.** It tracks what's known and recommends what to do next; it does not replace the underlying tools.

2. **External tools handle execution.** NetExec (nxc), impacket scripts, bloodhound-python, nanodump, pypykatz, hashcat — these do the work. AdPack calls them through the `DirectoryProvider` interface and the pluggable `Transport` layer.

3. **Core value is the state machine + evasion + planner.** The three differentiators are:
   - State-grounded execution (`ADState` tracks everything, gaps guide next actions)
   - Evasion profiles with cascading credential acquisition
   - Weighted privilege path planning (`planner/planner.go`) using Dijkstra over the edge graph with multi-dimensional scoring (operational cost, detection risk, execution risk, tooling gap) and configurable policies

4. **Pluggable transport.** Commands execute through `Transport` interface: local exec, SOCKS5 proxy, or Sliver C2 implant. Swap transports without changing module logic.

5. **Edge event sourcing.** Privilege edges are mutated through a reducer pattern (`ReduceEdgeEvent` in `core/edge_event.go`). Events are append-only per edge key, enabling audit trails, confidence tracking, staleness detection, and degradation.

6. **Identity normalisation.** `HostRef{Name, Domain}` is the canonical identity key. All values normalised to uppercase. `ResolveComputerRef` and `ResolveSessionRef` collapse LDAP + SMB observations to the same key.

7. **Session portability.** Engagement state is serializable to portable JSON envelopes (`core/session.go`). Sessions can be exported, imported, and transferred across machines.

## Package Layout

```
cmd/            — CLI commands (cobra)
config/         — YAML config loading and validation
core/           — Domain model: state, edges, events, sessions, reports
internal/
  bloodhound/   — BloodHound data collection and ingestion
  cracker/      — Hashcat cracking pipeline (worker pool + queue)
  executorbackend/ — Capability executors (DCSync, RBCD, ADCS, etc.)
  resolver/     — Identity resolution and normalisation
  runtime/      — Process supervision and lifecycle
  transport/    — Transport implementations (local, proxy, sliver)
modules/        — Attack modules: discovery, enumeration, privesc, etc.
planner/        — Weighted attack path planning (Dijkstra + policies)
storage/        — SQLite persistence layer (AES-256-GCM encrypted)
tools/          — External tool wrappers
tui/            — Terminal UI (Bubble Tea)
utils/          — Shared utilities: theme, command execution, logging
```

## Build & Test

```bash
go build -o adpack .                 # compile
make build                           # or via Makefile (outputs to bin/adpack)
make test                            # go test -v -race -coverprofile=coverage.out ./...
make lint                            # golangci-lint run ./...
make vet                             # go vet ./...
```
