# adpack — Domain Language

## Mission
adpack is a state-aware AD attack tool for red teams and pentesters. Tracks evidence, detects gaps, suggests next steps, dumps creds from AD.

## Core Concepts

| Term | Definition |
|------|------------|
| **Phase** | One of 9 sequential AD attack stages: discovery → enumeration → credential_acq → session_harvest → graph_analysis → lateral → validation → privesc → persistence |
| **State** | SQLite snapshot of hosts, users, creds, sessions, phase status |
| **Gap** | Missing prerequisite — e.g., "no hosts discovered", "no creds acquired" |
| **Evidence** | Timestamped tool execution record |
| **Pipeline** | Sequence of tool executions for cred acquisition (e.g., mimikatz→donut→netexec→pypykatz) |
| **Evasion Profile** | Config for delivery method, injection technique, pre-conditions for LSASS dump |
| **Target** | Remote Windows host (SMB/WMI/WinRM) |
| **Pre-condition** | Defensive measure before dump — e.g., killing Defender via UnDefend, freezing EDR via EDR-Freeze |
| **HostRef** | Canonical identity key for a machine. Every observation surface (LDAP, SMB sessions) collapses to the same HostRef when referring to the same host |
| **ProviderEvent** | Acquisition-boundary event envelope recording one provider call outcome (method, transport, duration, entity count, raw stdout/stderr) |
| **Identity Drift Snapshot** | Structured counters (resolved, unresolved, mismatches, duplicates) emitted per session harvest run, measuring how well identity converges under real traffic |

## Phase Dependencies
```
discovery → enumeration → credential_acq → session_harvest → lateral
                        → graph_analysis  → validation
                                          → privesc        → persistence
```

Actual dependency rules from code:
- **discovery**: no dependencies
- **enumeration**: depends on discovery
- **credential_acq**: depends on enumeration
- **session_harvest**: depends on enumeration + credential_acq
- **graph_analysis**: depends on enumeration
- **lateral**: depends on credential_acq + session_harvest
- **validation**: depends on credential_acq
- **privesc**: depends on enumeration + graph_analysis
- **persistence**: depends on credential_acq + privesc

## Evasion Profiles
13 profiles: minimal, standard, aggressive, bypass, bof, fork, byovd, coldwer, undefend, bluehammer, phantomkiller, miniplasma, custom
Each selects delivery (donut/bof/exe) + optional pre-conditions (Defender kill, EDR freeze, kernel driver). `BaseProfileFor(name)` collapses a tactic profile back to its operating posture (minimal / standard / aggressive / bypass / custom).

## Tool Ecosystem
| Tool | Role |
|------|------|
| NetExec (nxc) | SMB/WMI/WinRM remote execution, file transfer, auth testing. The canonical exec-method failover order used by `RunFailover` is **wmiexec → smbexec → atexec**, with a per-attempt timeout so any single stuck transport is bounded |
| nanodump | LSASS minidump with evasion techniques (fork, snapshot, WER) |
| go-mimikatz | Go port of mimikatz for sekurlsa::logonpasswords, dcsync |
| pypykatz | Offline LSASS dump parsing |
| UnDefend | Defender DOS — passive (block updates) or aggressive (kill) |
| BlueHammer | Defender RPC exploit for SAM hive leak via VSS |
| EDR-Freeze | WerFaultSecure PPL bypass to freeze EDR processes |
| PhantomKiller | Lenovo BootRepair.sys BYOVD — IOCTL-based EDR process termination |
| MiniPlasma | Cloud Filter API race (CVE-2020-17103) → SYSTEM shell |
| impacket-secretsdump | DRSUAPI dump for Golden Ticket forge + DCSync |
| impacket-ticketer | Forge TGTs given krbtgt hash + Domain SID |
| impacket-getST | S4U2self for delegation/RBCD attacks |
| impacket-dacledit | Native LDAP DACL write for AdminSDHolder backdoor |
| impacket-rbcd | RBCD configuration on victim computer object |
| impacket-lookupsid | Domain SID resolution for ticket forging |
| bloodyAD | LDAP attack tool used as fallback for AdminSDHolder + RBCD when impacket modules absent |

## Provider Layer

The provider boundary separates acquisition from interpretation:

| Layer | Responsibility | Files |
|-------|---------------|-------|
| **Provider interface** | Defines `DirectoryProvider` with EnumerateComputers, EnumerateGPOs, EnumerateADCSTemplates, EnumerateSessions | `core/provider.go` |
| **NetExec provider** | Routes enumeration via nxc LDAP/SMB with fallback (e.g., GPO falls back from LDAP --gpos to SMB gpolocal) | `modules/netexec_provider.go` |
| **Parsers** | Format-specific extraction. Two-stage grammar for computers: `DOMAIN\COMPUTER$` (qualified) or `COMPUTER$` (bare with injected domain) | `modules/netexec_parsers.go`, `modules/parserutil.go` |
| **Provider events** | Every method call emits a `ProviderEvent` (method, transport, duration, entity count, raw stdout/stderr) | `core/provider.go`, `core/jsonl_sink.go` |

## Identity Normalisation

Observations from different surfaces are collapsed to a canonical `HostRef{Name, Domain}`:

```
LDAP computer object  → ResolveComputerRef(name, domain)
SMB session username  → ResolveSessionRef(username, fallbackDomain)
```

Resolution rules for sessions:
1. `DOMAIN\NAME$` → extract both directly
2. `NAME$` → attach fallbackDomain
3. no trailing `$` → not a machine account (returns false)

## Operational Primitives
| Primitive | Purpose |
|-----------|---------|
| `tools.NetExec.RunFailover` | Canonical exec-method failover: **wmiexec → smbexec → atexec**. Each method gets the same per-attempt timeout; the first one that returns (success or clean failure) wins. Use this for everything *except* SYSTEM-context proof. |
| `tools.NetExec.RunSystemCheck` | **smbexec → atexec only** — deliberately skips wmiexec. Used by privesc to confirm SYSTEM. wmiexec runs commands under the authenticated user's token via DCOM/WMI and frequently does NOT yield SYSTEM. smbexec drops a temporary service and atexec uses Task Scheduler — both run as LocalSystem, so they're the only reliable failover paths for SYSTEM proof. |
| `tools.Deploy` | Hash + randomized-name SMB upload; returns remote path + SHA256 for evidence |
| `tools.CleanupRemote` | Best-effort delete of dropped artifacts (paired with `defer`) |
| `tools.DeployAndExec` | One-shot deploy → exec → optional retrieve → cleanup; for self-contained payloads |
