# adpack Usage Guide

Usage guide for adpack.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Attack Phases](#attack-phases)
- [Evasion Profiles](#evasion-profiles)
- [Command Reference](#command-reference)
- [Workflows](#workflows)
- [Tool Integration](#tool-integration)

## Installation

### ⚫ Automated Setup

Run `./setup.sh` to install everything:

```bash
git clone https://github.com/Yenn503/adpack.git
cd adpack
chmod +x setup.sh
./setup.sh
source ~/.bashrc
```

Installs deps, builds tools, configures environment.

### ⚪ Prerequisites

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

### ⚫ Build

```bash
git clone https://github.com/Yenn503/adpack.git
cd adpack
go build -o adpack .
sudo mv adpack /usr/local/bin/
```

### ⚪ Verify

```bash
adpack version
adpack status
```

## Configuration

### ⚫ Default Config

adpack works without config. State stored in `~/.adpack/state.db`.

### ⚪ Custom Config

Create `~/.adpack/config.yaml`:

```yaml
# Database location
db_path: "~/.adpack/state.db"

# Tool paths (auto-detected if in PATH)
nxc_path: "netexec"
bh_python: "bloodhound-python"

# Viper (Neo4j) connection for BloodHound queries
viper:
  enabled: false
  host: "localhost"
  port: 7687
```

## Attack Phases

### 1. Discovery

Finds DCs and network layout.

```bash
# Manual target
adpack run discovery --target 10.0.0.5

# Auto-discovery via LDAP ping
adpack run discovery
```

**Output**: Discovered hosts with DC status, open ports, OS detection.

### 2. Enumeration

Grabs users, computers, groups via LDAP.

```bash
adpack run enumeration --target 10.0.0.5
```

**Features**:
- Extracts 56+ user attributes
- Detects creds in user descriptions
- Finds admin and DA accounts
- Enumerates computer objects

### 3. Credential Acquisition

Dumps creds using evasion profile.

```bash
# Standard profile (Donut + go-mimikatz)
adpack run credential_acq -e standard -t 10.0.0.5

# Advanced evasion (EDR freeze + nanodump)
adpack run credential_acq -e coldwer -t 10.0.0.5

# Advanced evasion (Defender RPC technique)
adpack run credential_acq -e bluehammer -t 10.0.0.5
```

**Methods**:
- LSASS memory dumps
- Kerberoasting
- AS-REP roasting
- Password spraying
- NTDS.dit extraction

### 4. Session Harvesting

Finds active user sessions on domain systems and measures identity convergence.

```bash
adpack run session_harvest --target 10.0.0.5
```

**Methods**:
- NetExec SMB session enumeration (`--loggedon-users`)
- Per-host domain resolution for session identity
- Identity drift snapshot (resolved/unresolved/duplicate counters)

### 5. Graph Analysis

Collects AD structure for attack path mapping.

```bash
# Collect BloodHound data
adpack run graph_analysis --target 10.0.0.5

# Query specific paths (stub — Neo4j integration coming soon)
adpack query "MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name"
```

### 6. Lateral Movement

Lateral movement with validated creds.

```bash
adpack run lateral --target 10.0.0.6
```

**Methods**:
- PSExec (smbexec)
- WinRM
- Schtasks (atexec)

### 7. Validation

Tests creds across SMB, LDAP, WinRM, RDP.

```bash
# Validate all creds
adpack validate

# Validate against specific host
adpack validate --target 10.0.0.5
```

**Protocols Tested**:
- SMB (port 445)
- LDAP (port 389)
- WinRM (port 5985)
- RDP (port 3389)

**Detection**:
- Admin rights via "Pwn3d!" indicator
- Lateral movement viability
- Protocol-specific access levels

### 8. Privilege Escalation

Checks for misconfigs and vulnerabilities for privesc.

```bash
adpack run privesc --target 10.0.0.5
```

**Techniques**:
- ACL abuse
- ADCS vulnerability checks
- RBCD attacks
- GPP passwords

### 9. Persistence

Deploys long-term access mechanisms against a domain controller. Each technique
is independently attempted; missing tools or insufficient privilege skip that
technique rather than failing the whole phase.

```bash
adpack run persistence --target 10.0.0.5
```

**Methods (all real, all gated by tool availability):**

| Technique | Implementation | External tool |
|-----------|----------------|----------------|
| Scheduled task (onlogon, SYSTEM) | `schtasks /create` via failover exec | NetExec only |
| DSRM password-reuse logon | `reg add HKLM\…\Lsa /v DSRMAdminLogonBehavior /d 2` | NetExec only |
| Golden Ticket forge | `secretsdump -just-dc-user krbtgt` → `lookupsid` for SID → `ticketer` writes ccache | impacket-secretsdump, impacket-lookupsid, impacket-ticketer |
| AdminSDHolder GenericAll | LDAP DACL write → SDProp propagates ACE every 60min | impacket-dacledit (preferred) or bloodyAD |
| Skeleton Key (informational) | Detected when go-mimikatz remote-exec is viable; flagged in evidence, **not** auto-deployed (high noise) | — |

**Operational notes:**
- Golden Ticket ccache lands at `/tmp/golden_<user>.ccache`; the operator
  exports `KRB5CCNAME=<path>` to authenticate as the forged user for follow-on commands.
- AdminSDHolder grants the *currently authenticated* user GenericAll. The ACE
  survives password resets because SDProp re-applies it every 60 minutes.
- DSRM is only meaningful on DCs and only over SMB/RPC — not over RDP.
- Use `adpack reset persistence` to clear evidence and the in-memory ccache references; on-target artifacts (scheduled task, AdminSDHolder ACE, DSRM regkey, Golden Ticket validity) must be reverted manually.

## Evasion Profiles

### Minimal

In-memory execution for labs.

```bash
adpack run credential_acq -e minimal -t 10.0.0.5
```

**Pipeline**:
1. Donut converts go-mimikatz to shellcode
2. Execute in-memory via NetExec
3. Parse output for creds

**Detection Risk**: 🟡 Medium (in-memory execution, no disk writes)

### Standard

Remote execution for enterprise.

```bash
adpack run credential_acq -e standard -t 10.0.0.5
```

**Pipeline**:
1. Donut wraps go-mimikatz
2. Upload via SMB
3. Execute via WMI/WinRM
4. Retrieve output
5. Parse creds

**Detection Risk**: 🟡 Medium (remote execution, temporary files)

### Aggressive

BOF execution for C2 integration.

```bash
adpack run credential_acq -e aggressive -t 10.0.0.5
```

**Pipeline**:
1. nanodump as Beacon Object File
2. Process forking for evasion
3. In-memory dump parsing

**Detection Risk**: 🟢 Low (BOF execution, no new processes)

### Fork

LSASS process cloning.

```bash
adpack run credential_acq -e fork -t 10.0.0.5
```

**Pipeline**:
1. Upload nanodump.exe
2. Execute with `--fork` flag
3. Clone LSASS process
4. Dump cloned process
5. Retrieve and parse

**Detection Risk**: 🟢 Low (process cloning, indirect access)

### BYOVD

Vulnerable driver for kernel access.

```bash
adpack run credential_acq -e byovd -t 10.0.0.5
```

**Pipeline**:
1. Upload RTCore64.sys
2. Load vulnerable driver
3. Patch LSASS protection
4. Dump memory
5. Unload driver

**Detection Risk**: 🟢 Very Low (kernel-level, bypasses PPL)

### ColdWer

Freezes EDR during dump via WerFaultSecure PPL bypass.

```bash
adpack run credential_acq -e coldwer -t 10.0.0.5
```

**Pipeline**:
1. Upload EDR-Freeze.exe
2. Identify EDR processes
3. Freeze EDR for 3 seconds
4. Dump LSASS during freeze window
5. Resume EDR

**Detection Risk**: 🟢 Very Low (EDR blind during dump)

**Technique**: Freezes EDR processes. EDR can't see the dump.

### UnDefend

Kills Defender before dumping via Nightmare Eclipse technique.

```bash
adpack run credential_acq -e undefend -t 10.0.0.5
```

**Pipeline**:
1. Upload UnDefend.exe
2. Kill MsMpEng.exe
3. Block definition updates
4. Dump LSASS
5. Extract creds

**Detection Risk**: 🟢 Low (Defender disabled)

**Technique**: Kills Defender via service dependency method. Bypasses tamper protection.

### BlueHammer

Advanced RPC technique for SAM extraction from Nightmare Eclipse leaks.

```bash
adpack run credential_acq -e bluehammer -t 10.0.0.5
```

**Pipeline**:
1. Upload FunnyApp.exe
2. Leverage CVE-2026-33825 (Defender RPC)
3. Trigger VSS snapshot
4. Extract SAM hive
5. Parse local account hashes

**Detection Risk**: 🟢 Very Low (advanced technique, no LSASS access)

**CVE Details**: Defender RPC bug lets unprivileged users dump SAM via VSS. No admin needed. No LSASS alerts. From Nightmare Eclipse leaks.

**Assessment Value**: Tests if org can detect advanced cred theft. Simulates APT tradecraft.

**Build status**: Requires Visual Studio 2022 on Windows (MSVC, RPC IDL, Windows SDK). Cannot be cross-compiled from Linux — see SETUP.md for details.

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

Runs attack phase.

```bash
adpack run <phase> [flags]

Flags:
  -t, --target string             Target host IP or hostname
  -e, --evasion-profile string    Evasion profile (default "standard")
  -x, --execute                   Execute planned privilege escalation paths
      --provider-log string       File path for structured provider event logging (JSONL)
```

#### autorun

Auto-runs attack chain.

```bash
adpack autorun [flags]

Flags:
  -t, --target string             Target host IP or hostname
  -e, --evasion-profile string    Evasion profile (default "standard")
  -x, --execute                   Execute planned privilege escalation paths
  -m, --max int                   Maximum phases to run (0 = unlimited)
      --skip-fail                 Continue past failed phases
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
  -t, --target string    Target host (validates against all if not specified)
```

### State Management

#### reset

Reset phase status or entire state.

```bash
adpack reset <phase>    # Reset specific phase
adpack reset state      # Clear entire database
```

#### phases

List all phases with status and dependencies.

```bash
adpack phases
```

#### profiles

Show available evasion profiles.

```bash
adpack profiles
```

### Utility Commands

#### interactive

Opens TUI dashboard.

```bash
adpack interactive
```

#### ingest

Imports tool output.

```bash
adpack ingest <file>
```

#### query

Run Cypher query against BloodHound data.

```bash
adpack query "MATCH (u:User) RETURN u.name LIMIT 10"
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

### Advanced Evasion Workflow

```bash
# 1. Enumerate target
adpack run enumeration --target 10.0.0.5

# 2. Use advanced technique to disable Defender
adpack run credential_acq -e bluehammer -t 10.0.0.5

# 3. Chain with LSASS dump
adpack run credential_acq -e undefend -t 10.0.0.5

# 4. Validate extracted creds
adpack validate

# 5. Lateral movement
adpack run lateral --target 10.0.0.6
```

### Nightmare Eclipse Techniques

Orchestrates techniques from Nightmare Eclipse leaks. Nation-state level methods. Helps orgs:

1. **Test defences against APT-level attacks**
2. **Find blind spots in EDR/AV**
3. **Check if security controls work**
4. **Build detection for advanced attacks**

**When to use:**
- Client has mature security controls (EDR, SIEM, SOC)
- Assessment scope includes APT simulation
- Testing detection and response capabilities
- Validating security investments against real-world threats

**Responsible use:**
- Only on authorised targets with explicit permission
- Document all techniques used for client reporting
- Help client develop detection capabilities
- Follow responsible disclosure for any new vulnerabilities found

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

Main tool for remote exec and enum.

**Supported Protocols**:
- SMB: File sharing, remote execution
- LDAP: User/computer enumeration
- WinRM: PowerShell remoting
- MSSQL: Database queries

**Usage in adpack**:
- Discovery: LDAP ping for DC detection
- Enumeration: `--users`, `--computers`, `--groups`
- Validation: Authentication testing across protocols
- Lateral: Remote command execution

### nanodump

LSASS dumping with evasion.

**Features**:
- `--fork`: Clone LSASS process before dumping
- `--snapshot`: Use VSS snapshots
- `--dup`: Duplicate handle technique

**Usage in adpack**:
- Fork profile: Process cloning
- Aggressive profile: BOF execution
- BYOVD profile: Kernel-level dumping

### go-mimikatz

Go port of mimikatz for cred extraction.

**Commands**:
- `sekurlsa::logonpasswords`: Extract plaintext passwords
- `sekurlsa::tickets`: Dump Kerberos tickets
- `lsadump::dcsync`: DCSync attack

### pypykatz

Offline LSASS dump parsing.

**Usage**:
- Parse nanodump output
- Extract creds from minidumps
- Support for multiple dump formats

## Troubleshooting

### No Hosts Discovered

```bash
# Verify network connectivity
ping 10.0.0.5

# Check NetExec installation
netexec --version

# Manual discovery
adpack run discovery --target 10.0.0.5
```

### Credential Acquisition Failed

```bash
# Check tool availability
which go-mimikatz
which nanodump

# Try different evasion profile
adpack run credential_acq -e fork -t 10.0.0.5

# Check logs
adpack status
```

### Validation Fails

```bash
# Verify creds manually
netexec smb 10.0.0.5 -u user -p password

# Check network access
netexec smb 10.0.0.5 -u user -p password --shares
```

## Best Practices

1. **Start with Discovery**: Always run discovery before other phases
2. **Validate Early**: Test creds immediately after acquisition
3. **Use Appropriate Evasion**: Match profile to target defences
4. **Check State Frequently**: Run `adpack status` to track progress
5. **Save Evidence**: Export logs and provider events for analysis
6. **Test in Labs**: Use VulnAD/GOAD before production engagements
7. **Document Findings**: Export state as JSON for reporting

## Security Considerations

- Only use on authorised targets
- Credentials are encrypted at rest using AES-GCM in SQLite
- Protect state database with appropriate permissions (chmod 600)
- **Credentials encrypted at rest with AES-GCM** — Use disk encryption and protect the encryption key for sensitive engagements
- Clean up after engagements: `adpack reset state`
- Advanced evasion techniques should be used responsibly and legally
- Follow responsible disclosure for vulnerabilities found

### Nightmare Eclipse Ethics

Nightmare Eclipse techniques mirror real adversary tradecraft. AdPack orchestrates these methods. Use to:

- **Help orgs defend against advanced threats**
- **Test security posture accurately**
- **Help blue teams build detection**
- **Prove if security controls work**

**Do not use to:**
- Cause harm or damage systems
- Access unauthorised systems
- Exfiltrate sensitive data without authorisation
- Demonstrate capabilities for malicious purposes

Red teams exist to make organisations more secure. These tools should strengthen defences, not weaken them.
