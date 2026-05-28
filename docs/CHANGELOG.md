# Changelog

## v0.4.0 — Full Kill Chain Coverage, C2 Transport, Visual Overhaul

### New Attack Techniques
- **Zerologon (CVE-2020-1472)**: `adpack zerologon check/exploit/dcsync/restore` — Netlogon EoP exploit with DC password reset and recovery workflow
- **noPac (CVE-2021-42278/42287)**: `adpack nopac check/exploit/dcsync/scan` — SAM account impersonation + PAC-less TGT chain

### New CLI Commands (12)
- **Session management**: `adpack session save/load/list/delete/export/import` — full engagement state persistence as portable JSON envelopes
- **Kerberos manager**: `adpack kerb tgt/list/destroy/s4u` — TGT acquisition, ticket management, S4U2self/S4U2proxy delegation
- **ADCS exploitation**: `adpack adcs find/esc1-esc13/auth` — certipy wrapper for ESC1-13, PKINIT auth, NT hash extraction
- **Reporting**: `adpack report html/md/json` — standalone HTML, Markdown, and JSON engagement reports
- **Credential inventory**: `adpack cred list/export/status/verify` — credential management with hashcat/john export formats
- **DPAPI**: `adpack dpapi backupkey/masterkey/blob/vault/chrome/triage/credentials` — DPAPI blob decryption, browser credential extraction
- **gMSA**: `adpack gmsa list/read` — gMSA account enumeration and managed password retrieval
- **LAPS**: `adpack laps list` — LAPS password enumeration via LDAP
- **Coercion**: `adpack coerce printerbug/petitpotam/dfscoerce/shadow/all` — NTLM coercion attacks
- **Trust attacks**: `adpack trust list/keys/inter-realm/sidhistory` — domain trust enumeration and cross-forest ticket forging
- **Shadow copy**: `adpack shadow ntds/ifm/parse` — NTDS.dit extraction via VSS and local parsing
- **GPO abuse**: `adpack gpo create/runkey/task/localadmin/find` — GPO enumeration and ACL abuse

### Self-Contained Implementations
- **Native ADCS** (`modules/adcs_native.go`): LDAP discovery, template vulnerability analysis (ESC1-13), certificate generation via Go crypto/x509, PKINIT authentication, NT hash extraction
- **Native shadow copy** (`modules/shadow_native.go`): Direct NTDS.dit extraction via file copy (SYSTEM required), WMI-based extraction, local secretsdump parsing

### C2 Transport
- **Sliver transport** (`internal/transport/sliver/`): Execute commands through Sliver C2 implants via sliver-client CLI
- Session discovery, command execution, file upload/download through implant sessions
- Auto-matching of targets to active Sliver sessions by hostname/IP

### Visual Overhaul
- **Color scheme**: Replaced white/gray monochrome with vibrant electric palette
  - Primary: Electric Cyan (#00E5FF), Secondary: Soft Blue (#82B1FF)
  - Success: Bright Green (#00E676), Warning: Deep Orange (#FF9100)
  - Error: Vivid Red (#FF1744), Info: Bright Blue (#448AFF)
  - New accents: Pink (#FF80AB), Lime (#C6FF00), Pure Cyan (#18FFFF)
- Zero white colors in the entire UI

### Core Fixes
- **ADState concurrency**: `sync.RWMutex` protects concurrent access to state
- **Panic recovery**: `defer recover()` on crackWorker/crackMat goroutines
- **Graceful shutdown**: SIGINT/SIGTERM handler with context cancellation
- **Config validation**: `Validate()` method checks required fields and tool paths
- **Session health checks**: `ValidateSessionHealth()` on session load detects orphaned creds, missing hosts, nil phase maps
- **Secret masking**: `--show-secrets` flag on `cred list/export`
- **Version bump**: v0.3.0 → v0.4.0

### Bug Fixes (v0.4.0 patch)
- **GenerateJSONReport**: Fixed stub that always returned an error — now properly encodes JSON via `encoding/json`
- **cred.go**: Handle `json.MarshalIndent` errors in `credListCmd` and `credExportCmd` instead of ignoring
- **validate.go**: Removed `MiniPlasma.exe` from tools check (deprecated tool)
- **adcs_native.go**: Removed dead import guard code (`var _ = asn1.NullRawValue`)
- **sliver.go**: Removed dead import guard code (`var _ = core.HostRef{}`)

### Documentation
- README updated with full command table (24 commands)
- All 5 docs created and aligned with current codebase (USAGE.md, SETUP.md, CONTEXT.md, CONTRIBUTING.md, CHANGELOG.md)
- CHANGELOG added for v0.4.0

## v0.3.0 — Production Hardening & Profile Simplification

### Evasion Profiles Simplified
- Cut from 7 tactic profiles to 3 base profiles: standard, bypass, custom
- Removed: minimal, aggressive, nanodump, pplshade, edrfreeze, undefend, phantomkiller, dcsync
- All credential acquisition now routes through mimikatz or UnDefend pre-condition
- Dead tool wrappers removed (bluehammer.go, pplshade.go)

### SOCKS5 Proxy Transport
- New `internal/transport/proxy` for routing through C2 implants via proxychains4
- Configurable via `proxy_address` in config.yaml or `ADPACK_PROXY` env var
- Local transport unchanged; proxy transport wraps it transparently

### Timing Controls
- New `core.TimingConfig` with DelayMs, Jitter, MaxConcurrent fields
- Configurable in config.yaml under `timing:` section
- `Jitter` adds random variation for opsec-safe timing

### TUI Improvements
- Added computers count to status bar
- Top privilege edges summary table
- Running phase warning indicator
- Color-coded phase statuses
- Autorun key (`a`) for one-key full chain
- Error state display
- Dynamic header with timestamp

## v0.3.0 — Kill Chain Hardening, AV Evasion, Output Beautification

### Kill Chain Fixes

- **Validation phase no longer blocks privesc**: Hash-only credentials (AS-REP/Kerberoast) are skipped during validation since Kerberos hashes cannot authenticate via SMB/LDAP. Already-validated credentials now count toward phase success. Previously a single uncracked hash would fail the entire validation phase and stop the autorun before privesc could execute.
- **NTLM hash parsing fixed**: `ParseNTLMOutput` now uses a regex (`USER:RID:LM:NTHASH:::`) that correctly extracts usernames from nxc output regardless of the SMB prefix format. No more `SMB  192.168.57.22  445  CASTELBLACK  Administrator` leaking into username fields.
- **Credential acquisition pipeline**: `executeMimikatzPipeline` now falls back to `nanodump` when `go-mimikatz` is unavailable, instead of failing immediately.

### AV Evasion

- **Automatic AV kill**: `runUnDefendKill` deploys and executes UnDefend.exe `--kill` (aggressive mode) after SYSTEM access is confirmed. No profile flag gating — runs automatically.
- **Post-SYSTEM flow**: SYSTEM check → UnDefend --kill → deep credential dump. AV detection via `nxc enum_av` removed (requires admin, unreliable). UnDefend runs blind — safe if Defender isn't present.
- **UnDefend.exe symlink**: Points to adpack root copy for consistent availability.

### Deep Credential Dump Pipeline

- **`runDeepCredDump`**: Cascading credential extraction after AV disabled:
  - Tier 1: `go-mimikatz` (richest output: plaintext passwords + NTLM hashes)
  - Tier 2: `nanodump` + `pypykatz` (LSASS dump, reliable fallback)
  - Graceful degradation with styled output at each tier
- **Removed**: Broken real `mimikatz.exe` deployment (Kali wrapper script, parsing mismatches, Defender alerts).

### Output Beautification

- **All privesc output now uses styled helpers**: Every `fmt.Println("[*]...")` and `fmt.Printf("[!]...")` replaced with `utils.Step`, `utils.StepOk`, `utils.StepWarn`, `utils.StepInfo`, `utils.EdgeDisplay`, `utils.Finding`.
- Consistent Lipgloss styling across: GPP check, ADCS enumeration, RBCD, ACL enumeration, MSSQL impersonation, linked servers, delegation, BloodHound, path planning, SYSTEM check, AV kill, deep cred dump, child-to-parent escalation.

### Repository Hygiene

- **`adpack_v030dev` binary untracked**: Added to `.gitignore`, removed from git tracking.
- **`UnDefend.exe`**: Already covered by `*.exe` gitignore pattern.

### Known Limitations

- `go-mimikatz` requires Windows to build (uses `go generate` with Windows PE packer). Falls back to nanodump+pypykatz automatically.
- ESC1/ESC4/ESC7/ESC8 exploitation detected but not yet auto-exploited.
- Hash cracking (hashcat) integrated via `internal/cracker/worker.go` — NTLM/krb5tgs hashes auto-enqueued, cracked creds materialized into DB. GPU cracking via `--hashcat-path` flag.

## v0.2.0 — Provider Layer, Identity Normalisation, Documentation Overhaul

### Architecture

- **Provider boundary (`core/provider.go`)**: Acquisition layer quarantined behind `DirectoryProvider` interface. Orchestration no longer touches stdout, parsing, or transport.
- **Provider events (`core/provider.go`, `core/jsonl_sink.go`)**: Every provider call emits a `ProviderEvent` envelope (method, transport, duration, entity count, raw stdout/stderr) to a thread-safe `ProviderEventSink`. JSONL sink included for self-contained replay artefacts.
- **Identity normalisation (`core/hostref.go`, `core/identity.go`)**: `HostRef{Name, Domain}` canonical identity key. `ResolveComputerRef` and `ResolveSessionRef` are pure, stateless functions that collapse LDAP + SMB observations to the same key. All values normalised to uppercase for AD case-insensitive comparison.
- **Parser isolation (`modules/netexec_parsers.go`)**: All format-specific extraction debt moved out of orchestration. `parserutil.go` provides shared regexes (`DomainUserRe`, `GPOGUIDRe`, `ComputerBareRe`) and `IsNoiseLine`.
- **Two-stage computer grammar**: `DOMAIN\COMPUTER$` (fully qualified) + bare `COMPUTER$` via whitespace-delimited token matching to prevent false positives from `$PATH`, error strings, etc.

### Parser Fixes

- **DC detection**: `strings.Contains(lower, "server")` replaced with `"windows server"` / `"domain controller"` checks to prevent false positives.
- **GPO name parsing**: `strings.TrimLeft` (cutset behaviour) replaced with `strings.TrimPrefix` for correct prefix removal.
- **Session harvest**: Regex-based `parseSMBSessions` with `DOMAIN\user` extraction, `(from x.x.x.x)` source parsing, and dedup.
- **Graph analysis parsers**: `parseGPOs` uses `{GUID}` regex. `parseComputers` uses `DOMAIN\COMPUTER$` regex. `parseADCSTemplates` extracts `ESC\d+`.
- **LDIF GPO parser (`parseLDAPGPOs`)**: New LDIF block parser for `ldapsearch` output, extracts cn (GUID) and displayName per entry.

### GPO Fallback Fix

- **`gpolocal` → `ldapsearch`**: Replaced broken `gpolocal` nxc module (removed in v1.5.1) with direct `ldapsearch` LDAP query against `CN=Policies,CN=System` configuration partition. `EnumerateGPOs` now falls back to `ldapsearch` when `nxc ldap --gpos` returns empty or fails. Returns empty GPO list (not error) on missing GPOs, so orchestration reports `0 GPO(s)` instead of a noisy failure.
- **`tools/ldapsearch.go`**: New tool wrapper for `ldapsearch` CLI. `QueryGPOs` constructs the correct `-b` DN from domain components, binds as `user@domain` via LDAP, and queries for `groupPolicyContainer` objects.
- **GPO enumeration now works**: Real GOAD-Light test shows `2 GPOs enumerated` (Default Domain Policy + Default Domain Controllers Policy) vs the previous broken fallback error dump.

### Setup Script (`setup.sh`)

- **PhantomKiller**: Now downloads pre-built release from GitHub (PhantomKiller.zip, 88KB). Falls back to cloning + building if download fails.
- **MiniPlasma**: Now downloads pre-built release from GitHub (1.2MB exe). Falls back to `mcs` build.
- **UnDefend**: Now attempts MinGW cross-compile with `-DUNICODE`. Removed dead APTortellini fallback (404).
- **BlueHammer**: No more broken build attempt — clones source, prints clear VS 2022 instructions.
- **SweetPotato**: Removed from install flow (retired).
- **Generated `config.yaml`**: Now matches actual `Config` struct (`nxc_path`, `bh_python`, `viper`).
- **Build command**: `go build -o adpack .` instead of `main.go`.

### CLI

- `--provider-log` flag added to `autorun` and `run` commands for structured event logging (JSONL).
- `--domain`, `--user`, `--password` seed credential flags added to `autorun`.
- Unused `state` parameter removed from `runMiniPlasmaProbe`.

### Identity Drift Accounting

- Per-harvest-run drift snapshot printed at end of `session_harvest`: counters for resolved, unresolved, machine accounts, domain mismatches, duplicate host refs.
- Per-host domain resolution for session identity (not global `state.Hosts[0]`).

### Tests

- 7 parser variance tests for `parseComputers` (bare, fully-qualified, empty, noise, non-computer, dedup, mixed formats).
- Multi-domain identity stability test (`TestParseComputers_MultiDomainIdentity`) using real GOAD-Light multi-DC output.
- Cross-observation collapse test (`TestHostRef_CrossObservationCollapse`) — 4 sub-tests.
- 39+ tests passing across all packages.

### Documentation

All 5 documentation files aligned with codebase:

- **CONTEXT.md**: Phase dependency DAG, HostRef/identity normalisation, ProviderEvent/JSONLSink, provider layer table, identity drift concept.
- **README.md**: 11→13 profiles, phase ordering fixed (session_harvest 4, graph_analysis 5, lateral 6, validation 7), example output updated (drift snapshot, 2 ADCS templates), config example fixed, tool provenance table added.
- **USAGE.md**: Build command, config example, phase ordering, new flags, session harvest methods, DCOM/LDAP logon queries/WMI process enumeration removed.
- **SETUP.md**: Build command, config example, tool binary status (PhantomKiller/MiniPlasma release-based, BlueHammer VS 2022 note), best-effort disclaimer.
- **CONTRIBUTING.md**: Project structure (engine/ removed), `go test ./...` replaces `make test`, tool wrapper example updated.
- **docs/CHANGELOG.md**: Added.

### Removed

- `engine/` package (dead code, replaced by provider layer).
- `tools/bootstrap.go`, `tools/donut.go`, `tools/executors.go`, `tools/ldap.go`, `tools/scarecrow.go`, `tools/syswhispers.go` (unused stubs).
- `tools/miniplasma_test.go`, `tools/phantomkiller_test.go` (tests for removed stubs).
- SweetPotato from install flow and privesc (replaced by smbexec/atexec).

### Known Limitations

- BlueHammer cannot cross-compile on Linux (MSVC + RPC IDL + Windows SDK). Requires VS 2022 on Windows.
- `--smb-sessions` flag deprecated in nxc v1.5.1 — not yet migrated to `--loggedon-users`.
- Asset URL fragility: release downloads use hardcoded URLs that may break if upstream renames artifacts.
