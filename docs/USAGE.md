# adpack Usage Guide

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Attack Phases](#attack-phases)
- [Evasion Profiles](#evasion-profiles)
- [Command Reference](#command-reference)
- [Workflows](#workflows)
- [Tool Integration](#tool-integration)

## Installation

### Automated Setup

Run `./setup.sh` to install everything:

```bash
git clone https://github.com/Yenn503/adpack.git
cd adpack
chmod +x setup.sh
./setup.sh
source ~/.bashrc
```

### Prerequisites

```bash
# Install Go 1.25+
wget https://go.dev/dl/go1.25.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.10.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install NetExec
pipx install netexec

# Optional tools for evasion
# Donut: https://github.com/TheWover/donut
# nanodump: https://github.com/fortra/nanodump
# go-mimikatz: https://github.com/vyrus001/go-mimikatz
```

### Build

```bash
git clone https://github.com/Yenn503/adpack.git
cd adpack
go build -o adpack .
sudo mv adpack /usr/local/bin/
```

### Verify

```bash
adpack version
adpack status
```

## Configuration

### Default Config

adpack works without a config file. State is stored in `~/.adpack/state.db`.

### Custom Config

Create `~/.adpack/config.yaml`. See [config.example.yaml](../config.example.yaml) for all options:

```yaml
db_path: ""
nmap_args: ["-T4", "-sn"]
nxc_path: "netexec"
bh_python: "bloodhound-python"

cracking:
  hashcat_path: "/usr/bin/hashcat"
  wordlist: "/usr/share/wordlists/rockyou.txt"
  rules: ["/usr/share/hashcat/rules/best64.rule"]
  timeout_seconds: 600

viper:
  enabled: false
  host: "localhost"
  port: 7687
```

### Scope Enforcement

Add a `scope` key to config.yaml to restrict targets to specific CIDR ranges:

```yaml
scope:
  - "10.0.0.0/8"
  - "192.168.1.0/24"
```

When scope is set, `adpack run --target` checks the target IP against the scope and rejects out-of-range targets. This is a safety net for production engagements.

## Attack Phases

### 1. Discovery

Finds DCs and network layout.

```bash
# Manual target
adpack run discovery --target 10.0.0.5

# Auto-discovery via LDAP ping
adpack run discovery
```

### 2. Enumeration

Grabs users, computers, groups via LDAP.

```bash
adpack run enumeration --target 10.0.0.5
```

### 3. Credential Acquisition

Dumps creds using an evasion profile.

```bash
# Standard profile
adpack run credential_acq -e standard -t 10.0.0.5

# Bypass profile (includes Defender neutralisation pre-flight)
adpack run credential_acq -e bypass -t 10.0.0.5
```

### 4. Session Harvesting

Finds active user sessions on domain systems.

```bash
adpack run session_harvest --target 10.0.0.5
```

### 5. Graph Analysis

Collects AD structure for attack path mapping.

```bash
adpack run graph_analysis --target 10.0.0.5
adpack query "MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name"
```

### 6. Lateral Movement

Moves between systems with validated creds.

```bash
adpack run lateral --target 10.0.0.6
```

### 7. Validation

Tests creds across SMB, LDAP, WinRM, RDP.

```bash
adpack validate
adpack validate --target 10.0.0.5
```

### 8. Privilege Escalation

Checks for misconfigs and vulnerabilities.

```bash
adpack run privesc --target 10.0.0.5
```

### 9. Persistence

Deploys long-term access mechanisms.

```bash
adpack run persistence --target 10.0.0.5
```

## Evasion Profiles

### Standard

Remote execution for enterprise. Default profile.

```bash
adpack run credential_acq -e standard -t 10.0.0.5
```

### Bypass

Standard profile with automatic UnDefend Defender neutralisation pre-flight.

```bash
adpack run credential_acq -e bypass -t 10.0.0.5
```

### Custom

User-defined pipeline for custom configurations.

```bash
adpack run credential_acq -e custom -t 10.0.0.5
```

## Command Reference

### Core Commands

#### status

Shows current state and gaps.

```bash
adpack status
adpack status --json  # JSON output for automation
```

#### next

Shows next phase and why.

```bash
adpack next
```

#### run

Runs a single attack phase.

```bash
adpack run <phase> [flags]

Flags:
  -t, --target string             Target host IP or hostname
  -e, --evasion-profile string    Evasion profile (default "standard")
  -x, --execute                   Execute planned privilege escalation paths
      --dry-run                   Show what would be done without executing
      --resume                    Resume phase execution, skipping completed hosts
      --provider-log string       File path for structured provider event logging (JSONL)
```

`--dry-run` prints the planned actions for a phase without actually executing them. Useful for reviewing what a phase will do before running it.

`--resume` skips hosts that were already processed in a previous run of the same phase. Marks failed hosts for re-execution and completed hosts as done.

#### autorun

Auto-runs the full attack chain.

```bash
adpack autorun [flags]

Flags:
  -t, --target string             Target host IP or hostname
  -e, --evasion-profile string    Evasion profile (default "standard")
  -x, --execute                   Execute planned privilege escalation paths
  -m, --max int                   Maximum phases to run (0 = unlimited)
      --skip-fail                 Continue past failed phases instead of stopping
      --domain string             Domain for seed credentials
      --user string               Username for seed credentials
      --password string           Password for seed credentials
      --provider-log string       File path for structured provider event logging (JSONL)
```

#### validate

Tests creds across protocols.

```bash
adpack validate [flags]

Flags:
  -t, --target string    Target host (validates against all hosts if not specified)
```

### Interactive Mode

#### interactive

Opens the TUI dashboard.

```bash
adpack interactive
```

Launches a terminal UI that shows:
- Phase completion status with colour-coded indicators
- Discovered hosts, users, and credentials
- Phase dependency chain with gap detection
- Live status updates

The TUI refreshes automatically from the SQLite state database. Use it to monitor progress during autoruns or inspect state between phases.

### State Management

#### reset

Resets phase status or entire state.

```bash
adpack reset <phase>    # Reset specific phase status
adpack reset state      # Clear entire database
```

#### phases

Lists all phases with status and dependencies.

```bash
adpack phases
```

#### profiles

Shows available evasion profiles.

```bash
adpack profiles
```

#### loot

Displays a comprehensive loot summary from the current state.

```bash
adpack loot
```

Shows credentials, validated creds, domain info, vulnerability coverage, and backdoor status.

### Utility Commands

#### ingest

Imports tool output.

```bash
adpack ingest <file>
```

#### query

Runs a Cypher query against the BloodHound graph (requires Neo4j connection).

```bash
adpack query "MATCH (u:User) RETURN u.name LIMIT 10"
```

### Flags

#### Global Flags

```bash
-c, --config string         Config file path
-d, --db string             Database path (default ~/.adpack/state.db)
    --hashcat-path string   Path to hashcat binary (overrides config)
    --wordlist string       Path to wordlist (overrides config)
    --rules string          Comma-separated hashcat rule files (overrides config)
    --crack-timeout int     Timeout per hash in seconds (overrides config)
```

## Cracking Pipeline

Extracted hashes are automatically enqueued into a background cracker pipeline:

1. Hashes are collected from Kerberoast, AS-REP roasting, and SAM/LSA dumps
2. Enqueued in a priority-ordered HashQueue (DA accounts first)
3. Cracked via hashcat with configurable rules and wordlist
4. Cracked credentials materialise into the state database
5. Triggers re-evaluation of privesc paths when new creds arrive

The cracker runs as a background goroutine, started on the first command. Configuration is in the `cracking` config section:

```yaml
cracking:
  hashcat_path: "/usr/bin/hashcat"
  wordlist: "/usr/share/wordlists/rockyou.txt"
  rules: ["/usr/share/hashcat/rules/best64.rule"]
  timeout_seconds: 600
```

Global flags override config values at runtime:

```bash
adpack run enumeration --target 10.0.0.5 --hashcat-path /opt/hashcat/hashcat
```

## Workflows

### Basic Workflow

```bash
# 1. Check initial state
adpack status

# 2. Discover DCs
adpack run discovery --target 10.0.0.5

# 3. Enumerate users
adpack run enumeration --target 10.0.0.5

# 4. Acquire creds
adpack run credential_acq --target 10.0.0.5

# 5. Validate creds
adpack validate

# 6. Check progress
adpack status
```

### Automated Workflow

```bash
# Run first 5 phases automatically
adpack autorun --target 10.0.0.5 --max 5

# Full automated chain
adpack autorun --target 10.0.0.5
```

### Resume After Interruption

```bash
# Start an autorun
adpack autorun --target 10.0.0.5 --max 4

# If it's interrupted, check status
adpack status

# Resume the next phase manually
adpack run credential_acq --target 10.0.0.5 --resume

# Or resume the full chain from where it left off
adpack autorun --target 10.0.0.5
```

### Preview Before Execution

```bash
# See what a phase will do without running it
adpack run credential_acq --target 10.0.0.5 --dry-run

# Validate the chain plan
adpack next
```

### Scoped engagement

```yaml
# In ~/.adpack/config.yaml:
scope:
  - "10.0.1.0/24"
```

```bash
# This will work
adpack run discovery --target 10.0.1.10

# This will be rejected
adpack run discovery --target 10.0.2.10
# Error: target 10.0.2.10 is outside allowed scope Scope{10.0.1.0/24}
```

### Advanced Evasion Workflow

```bash
# 1. Enumerate target
adpack run enumeration --target 10.0.0.5

# 2. Use bypass profile to neutralise Defender before dump
adpack run credential_acq -e bypass -t 10.0.0.5

# 3. Chain with Defender kill + dump
adpack run credential_acq -e bypass -t 10.0.0.5

# 4. Validate extracted creds
adpack validate

# 5. Lateral movement
adpack run lateral --target 10.0.0.6
```

### Multi-Host Workflow

```bash
# Enumerate multiple hosts
for ip in 10.0.0.{5..10}; do
  adpack run discovery --target $ip
done

# Validate creds across all hosts
adpack validate

# Check which hosts are accessible
adpack status
```

## Tool Integration

### NetExec

Main tool for remote exec and enumeration.

**Supported Protocols**:
- SMB: File sharing, remote execution
- LDAP: User/computer enumeration
- WinRM: PowerShell remoting
- MSSQL: Database queries

### nanodump

LSASS dumping with evasion techniques (fork, snapshot, WER).

### go-mimikatz

Go port of mimikatz for sekurlsa::logonpasswords, dcsync. Requires Windows build.

### pypykatz

Offline LSASS dump parsing.

## Troubleshooting

### No Hosts Discovered

```bash
ping 10.0.0.5
netexec --version
adpack run discovery --target 10.0.0.5
```

### Credential Acquisition Failed

```bash
which go-mimikatz
which nanodump
adpack run credential_acq -e nanodump -t 10.0.0.5
adpack status
```

### Validation Fails

```bash
netexec smb 10.0.0.5 -u user -p password
netexec smb 10.0.0.5 -u user -p password --shares
```

## Security Considerations

- Only use on authorised targets
- Credentials are encrypted at rest using AES-GCM in SQLite
- Protect state database with 600 permissions
- Use disk encryption for sensitive engagements
- Clean up after engagements: `adpack reset state`
- Scope enforcement helps prevent accidental targeting of out-of-range hosts
