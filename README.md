<p align="center">
  <img src="AdPackBanner.jpg" alt="AdPack Banner" width="100%">
</p>

<h3 align="center">Active Directory attack orchestration with state tracking</h3>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-white?style=for-the-badge&logo=opensourceinitiative&logoColor=black" alt="License">
  </a>
  <a href="https://go.dev">
    <img src="https://img.shields.io/badge/Go-1.25+-black?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-white?style=for-the-badge&logo=linux&logoColor=black" alt="Platform">
    <img src="https://img.shields.io/badge/Version-0.5.0-black?style=for-the-badge&logo=semver&logoColor=white" alt="Version">
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

Adpack runs AD attacks across 14 phases — initial access through cloud pillage. It tracks hosts, users, creds, tokens, and sessions in SQLite, shows what's missing, and chains phases together automatically.

### Quick Start

```bash
git clone https://github.com/Yenn503/AdPack.git
cd adpack && ./setup.sh && source ~/.bashrc

# Automated attack chain — seed creds, execute privesc paths
adpack autorun --target 10.0.0.5 \
  --domain corp.local \
  --user jsmith --password 'Password1' \
  --execute --skip-fail
```

### Example Output

<p align="center">
  <img src="adpack-demo.gif" alt="adpack autorun demo">
</p>

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
- Tracks state across phases so you know what's been done and what's left
- `autorun` chains phases together, `--resume` picks up where you left off
- `--dry-run` previews actions before running them
- Scope enforcement via CIDR whitelist in config
- TUI dashboard via `adpack interactive`

### Credential Operations
- Credential dump: nanodump+pypykatz, falls back to nxc SAM/LSA
- AV kill after SYSTEM: native reg add + sc stop + taskkill (no external binary)
- Kerberoasting and AS-REP roasting with automatic hash capture
- Hash cracking via hashcat (NTLM, krb5tgs, krb5asrep)
- Multi-protocol validation: SMB, LDAP, WinRM, RDP
- Flags admin rights and lateral movement options

### Evasion
- 3 profiles: `native` (reg-based AV kill), `pplshade` (BYOVD PPL bypass), `phantomkiller` (EDR process kill)
- AV kill runs automatically after SYSTEM access
- Internal credential acquisition pipeline supports PPLShade, MiniPlasma, PhantomKiller as fallback stages
- See the [evasion profiles table](#evasion-profiles) below

### Transport
Commands run through nxc/impacket for SMB, WinRM, WMI, and MSSQL. Sliver C2 transport available for executing through implants (`internal/transport/sliver/`). Swap in custom transports for any C2.

### Cracking
Extracted hashes queue into background hashcat workers. Cracked creds land in the state database and trigger privesc re-evaluation.

---

## Attack Phases

14 phases from initial access to cloud pillage:

```
00. Initial Access → 01. Discovery → 02. Enumeration → 03. Credential Acquisition
         ↓
04. Session Harvesting → 05. Graph Analysis → 06. Validation
         ↓
07. Privesc → 08. Cred Re-Acquisition → 09. Lateral → 10. Persistence

Cloud fork (parallel):
11. Cloud Enum → 12. Cloud Cred Acq → 13. Cloud Privesc → 14. Cloud Pillage
```

---

## Evasion Profiles

3 profiles for credential acquisition:

| Profile | What it does | When to use it |
|---------|-------------|----------------|
| `native` | reg add + sc stop + taskkill, then nanodump | Default — kills Defender, no extra binaries |
| `pplshade` | BYOVD PPL bypass via PPLShade + LECOMAx64.sys | LSASS is PPL-protected |
| `phantomkiller` | BYOVD process killer via PhantomKiller + PhantomKiller.sys | Need to kill EDR processes |

### Tool Provenance

| Tool | Source |
|------|--------|
| nanodump | Go binary, downloaded during setup |
| PPLShade | GitHub release (BYOVD) |
| PhantomKiller | GitHub release (BYOVD) |
| MiniPlasma | GitHub release — may require manual download |

### Pre-conditions

- **native** — Nothing extra needed. Runs reg + sc + taskkill after SYSTEM.
- **pplshade** — Needs `PPLShade.exe` + `LECOMAx64.sys` on target. Downloaded during setup.
- **phantomkiller** — Needs `PhantomKiller.exe` + `PhantomKiller.sys` on target. Downloaded during setup.

---

## Environment

Built on Windows + WSL2 (Ubuntu). Single Go binary — compile and drop on any Linux attack box. Windows tool binaries live in `exe/` alongside.

Tested on DreadGOAD-Light (3 VMware VMs, 2 forests) and VulnAD (Docker).

---

## Configuration

Create `adpack.yaml` in your project directory (or `~/.adpack/config.yaml`):

```yaml
domain: "corp.local"
profile: "native"

db_path: ""
nmap_args: ["-T4", "-sn"]
nxc_path: "netexec"
bh_python: "bloodhound-python"

seeds:
  - domain: "corp.local"
    user: "jsmith"
    password: "ChangeMe"

cracking:
  hashcat_path: "/usr/bin/hashcat"
  wordlist: "/usr/share/wordlists/rockyou.txt"
  rules: ["/usr/share/hashcat/rules/best64.rule"]
  timeout_seconds: 600

# Target scope: CIDR ranges allowed for attacks (optional safety net)
# scope:
#   - "10.0.0.0/8"
#   - "192.168.1.0/24"
```

Credentials are encrypted with AES-GCM in SQLite. The key file sits next to the database — keep both on an encrypted disk with 600 perms.

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

Installs Go 1.25+, NetExec, pypykatz, nanodump, PPLShade, PhantomKiller, and the adpack binary. ~5-10 minutes.

### Manual Installation

See [docs/SETUP.md](docs/SETUP.md).

---

## All Commands (v0.5.0)

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
| `adpack initial teams/device-code/consent-phish` | Initial access (Teams/OAuth) |
| `adpack cloud enum/cred-acq/privesc/pillage` | Cloud/Entra ID attacks |
| `adpack phases/profiles/loot/reset` | Utility commands |
| `adpack query [--preset <name>] [--list-presets]` | Cypher queries with preset library |

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
