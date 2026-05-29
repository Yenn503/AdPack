# AdPack Context

Domain language, architecture, and design decisions for adpack.

## Domain Language

### Core Concepts

- **Phase**: A discrete stage in the AD attack lifecycle. 14 phases from initial access to cloud pillage.
- **State (ADState)**: The accumulated knowledge about the target environment — hosts, users, creds, sessions, edges, phase progress.
- **Gap**: A missing prerequisite detected by state analysis (e.g., "no hosts discovered", "no credentials validated").
- **Edge (PrivilegeEdge)**: A directed privilege relationship between two AD principals (e.g., GenericAll, DCSync, HasSession).
- **Edge Event**: A state mutation applied to an edge via a reducer (validation, degradation, staleness).
- **HostRef**: Canonical identity key `{Name, Domain}` for a target machine. All values normalised to uppercase.
- **Credential**: A secret material (plaintext, NTLM hash, Kerberos ticket, certificate, token) bound to a domain user.
- **Session**: An active user logon session discovered on a target host.
- **Provider**: An abstraction over external tool execution. Emits structured `ProviderEvent` envelopes.
- **Transport**: Pluggable command execution interface (local, proxy/SOCKS5, Sliver C2).
- **Evasion Profile**: A named configuration controlling how credential acquisition tools are deployed (native, pplshade, phantomkiller).

### Phase Dependency DAG

```
initial_access
  └─ discovery
       └─ enumeration
            ├─ credential_acq (non-priv)
            │    ├─ session_harvest
            │    ├─ graph_analysis
            │    │    └─ validation
            │    └─ privesc
            │         ├─ credential_acq (re-run / spray)
            │         ├─ lateral
            │         │    └─ persistence
            └─ (enumeration feeds all downstream)

Cloud (parallel fork from initial_access):
initial_access → cloud_enum → cloud_cred_acq → cloud_privesc → cloud_pillage
```

### Credential Types

| Type | Description | Example |
|------|-------------|---------|
| `plaintext` | Cleartext password | `Password1` |
| `hash` | NTLM hash | `dbd13e1c4...` |
| `ticket` | Kerberos ticket (ccache/kirbi) | `Administrator@CORP.LOCAL.ccache` |
| `token` | Windows access token | (in-memory only) |
| `certificate` | PKI certificate (PFX/PEM) | `Administrator.pfx` |

### Edge Types

| Type | Description | Source |
|------|-------------|--------|
| `acl` | DACL-based privilege (GenericAll, WriteDacl, etc.) | BloodHound, daclread |
| `mssql_impersonation` | MSSQL user impersonation | MSSQL enumeration |
| `mssql_xp_cmdshell` | MSSQL command execution | MSSQL enumeration |
| `mssql_linked_server` | MSSQL linked server access | MSSQL enumeration |
| `adcs_esc1` | ESC1 certificate template | ADCS enumeration |
| `adcs_esc8` | ESC8 web enrollment | ADCS enumeration |
| `unconstrained_delegation` | Unconstrained delegation | BloodHound |
| `rbcd` | Resource-based constrained delegation | BloodHound |
| `shadow_cred` | Shadow credentials (KeyCredentialLink) | BloodHound |

### Edge Validation States

```
inferred → observed → validated
                    → stale
                    → degraded
                    → probabilistic
```

## Architecture

### Package Layout

```
adpack/
  cmd/            # CLI commands (cobra)
  config/         # YAML config loading and validation
  core/           # Domain model: state, edges, events, sessions, reports
  internal/
    bloodhound/   # BloodHound data collection and ingestion
    cracker/      # Hashcat cracking pipeline (worker pool + queue)
    executorbackend/  # Capability executors (DCSync, RBCD, ADCS, etc.)
    resolver/     # Identity resolution and normalisation
    runtime/      # Process supervision and lifecycle
    transport/    # Transport implementations (local, proxy, sliver)
  modules/        # Attack modules: discovery, enumeration, privesc, etc.
  planner/        # Attack path planning and recommendation
  storage/        # SQLite persistence layer
  tools/          # External tool wrappers (NetExec, nanodump, TeamsPhisher, etc.)
  tui/            # Terminal UI (Bubble Tea)
  utils/          # Shared utilities: theme, command execution, logging
```

### Key Design Decisions

1. **State-grounded execution**: Every action reads from and writes to `ADState`. The planner queries state to recommend next actions. No action is taken without state awareness.

2. **Provider boundary**: External tool execution is quarantined behind the `DirectoryProvider` interface. Orchestration never touches stdout, parsing, or transport directly. Every provider call emits a structured `ProviderEvent`.

3. **Identity normalisation**: `HostRef{Name, Domain}` is the canonical identity key. All values are normalised to uppercase. `ResolveComputerRef` and `ResolveSessionRef` collapse LDAP + SMB observations to the same key.

4. **Edge event sourcing**: Privilege edges are mutated through a reducer pattern (`ReduceEdgeEvent`). Events are append-only logged per edge key. This enables audit trails and confidence tracking.

5. **Pluggable transport**: The `Transport` interface abstracts command execution. Three implementations: local (direct exec), proxy (SOCKS5 via proxychains), Sliver (C2 implant).

6. **Cascading credential acquisition**: Credential dumping degrades gracefully: nanodump+pypykatz → nxc SAM/LSA. Each tier is attempted only if the previous fails.

7. **Concurrency safety**: `ADState` is protected by `sync.RWMutex`. Cracking pipeline runs in background goroutines with panic recovery.

8. **Session portability**: Engagement state is serializable to portable JSON envelopes. Sessions can be exported, transferred, and imported across machines.

### Data Flow

```
User Input (CLI)
  └─ cmd/*.go (cobra commands)
       └─ modules/*.go (attack logic)
            ├─ core/state.go (read/write ADState)
            ├─ internal/transport/ (command execution)
            ├─ internal/cracker/ (hash cracking)
            └─ storage/ (SQLite persistence)
                 └─ core/session.go (JSON export/import)
```

### Concurrency Model

- **Main goroutine**: CLI command execution, state mutations
- **CrackWorker goroutine**: Background hashcat job processing with panic recovery
- **CredentialMaterializer goroutine**: Polls crack queue for results, saves to DB
- **Signal handler goroutine**: Listens for SIGINT/SIGTERM, triggers graceful shutdown
- **State mutex**: `sync.RWMutex` protects all concurrent access to `ADState`

## Configuration

See `config.example.yaml` for the full reference. Key sections:

- `db_path`: SQLite database location (use `$HOME`, not `~`)
- `nxc_path`, `bh_python`: External tool paths
- `cracking`: Hashcat configuration (path, wordlist, rules, timeout)
- `proxy_address`: SOCKS5 proxy for transport routing
- `viper`: Neo4j connection for BloodHound graph queries
- `evasion`: Default evasion profile and auto AV kill toggle
- `scope`: Optional CIDR whitelist for attack targets

## Testing

```bash
go test ./...                    # Run all tests
go test -v ./modules/            # Verbose module tests
go test -cover ./...             # With coverage
```

Test coverage includes:
- Parser variance tests (computer, session, GPO parsing)
- Identity normalisation and cross-observation collapse
- Edge event reduction
- Credential acquisition pipeline
- State mutation and gap detection
