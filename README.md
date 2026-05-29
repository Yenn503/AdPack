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

Adpack runs AD attacks through 11 phases. It tracks hosts, users, creds, and sessions in SQLite, detects gaps, suggests next steps, and goes from recon to domain admin.

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

![adpack autorun demo](adpack-demo.gif)

*Full 11-phase autorun against GOAD v2 lab (recorded via asciinema). ~2.5M, 80 frames.*

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
- Cascading credential dump: nanodump+pypykatz → nxc SAM/LSA (graceful degradation)
- Automatic AV kill: native reg add + sc stop + taskkill (post-SYSTEM)
- Kerberoasting and AS-REP roasting with automatic hash capture
- Hash cracking pipeline via hashcat (NTLM, krb5tgs, krb5asrep)
- Multi-protocol validation across SMB, LDAP, WinRM, RDP
- Detects admin rights and lateral movement viability

### Evasion
- 3 evasion profiles: `undefend` (native AV kill), `pplshade` (PPL bypass), `phantomkiller` (EDR process kill)
- Automatic AV kill after SYSTEM access via native reg add + sc stop + taskkill
- Internal credential acquisition pipeline supports PPLShade, MiniPlasma, PhantomKiller as fallback stages
- See the [evasion profiles table](#evasion-profiles) below

### Transport Interface
Commands execute through the nxc/impacket CLI tools for SMB, WinRM, WMI, and MSSQL exec methods with automatic failover. The default `local` transport uses the operator's own network position. **Sliver C2 transport** is available for executing commands through Sliver implants (`internal/transport/sliver/`). Custom transports can be swapped in for any C2 framework.

### Cracking Pipeline
Extracted hashes (NTLM, Kerberoast, AS-REP) are automatically enqueued into a background hashcat worker pool. Cracked credentials materialise into the state database and trigger re-evaluation of privesc paths.

---

## Attack Phases

11 phases from recon to persistence:

<div align="center">

<table>
<tr>
<td align="center"><strong>01. Discovery</strong><br><sub>Find domain controllers and network topology</sub></td>
<td align="center">→</td>
<td align="center"><strong>02. Enumeration</strong><br><sub>Collect users, computers, groups via LDAP</sub></td>
<td align="center">→</td>
<td align="center"><strong>03. Credential Acquisition</strong><br><sub>Extract creds via nanodump, SAM, kerberoast</sub></td>
</tr>
<tr>
<td colspan="5" align="center">↓</td>
</tr>
<tr>
<td align="center"><strong>04. Session Harvesting</strong><br><sub>Find active user sessions on domain systems</sub></td>
<td align="center">→</td>
<td align="center"><strong>05. Graph Analysis</strong><br><sub>Map attack paths with BloodHound</sub></td>
<td align="center">→</td>
<td align="center"><strong>06. Validation</strong><br><sub>Test creds across SMB, LDAP, WinRM</sub></td>
</tr>
<tr>
<td colspan="5" align="center">↓</td>
</tr>
<tr>
<td align="center"><strong>07. Privesc</strong><br><sub>MSSQL→SYSTEM, AV kill, LSASS/SAM dump</sub></td>
<td align="center">→</td>
<td align="center"><strong>08. Credential Re-Acquisition</strong><br><sub>Spray new creds post-SYSTEM</sub></td>
<td align="center">→</td>
<td align="center"><strong>09. Lateral Movement</strong><br><sub>Move between systems with validated creds</sub></td>
</tr>
<tr>
<td colspan="3" align="center"></td>
<td align="center">→</td>
<td align="center"><strong>10. Persistence</strong><br><sub>Scheduled tasks, backdoor access</sub></td>
</tr>
<tr>
<td colspan="3" align="center"></td>
<td align="center">→</td>
<td align="center"><strong>11. Cleanup</strong><br><sub>Stop relay servers, restore state</sub></td>
</tr>
</table>

</div>

---

## Evasion Profiles

3 profiles for credential acquisition on real engagements:

| Profile | Technique | Use Case |
|---------|-----------|----------|
| `undefend` | Native AV kill (reg + sc + taskkill) + nanodump | Full chain with automatic Defender neutralisation |
| `pplshade` | BYOVD PPL bypass (PPLShade) → LSASS unprotected | When LSASS is PPL-protected |
| `phantomkiller` | BYOVD EDR process killer (PhantomKiller) | Kill MsMpEng and other EDR processes |

### Tool Provenance

| Tool | Source |
|------|--------|
| nanodump | Go binary, downloaded during setup |
| PPLShade | GitHub release (BYOVD) |
| PhantomKiller | GitHub release (BYOVD) |
| MiniPlasma | GitHub release — may require manual download |

### Pre-conditions

- **undefend** — Kills Defender via `reg add` (6 keys) + `sc stop WinDefend` + `taskkill /f /im MsMpEng.exe` after SYSTEM access. No external binary needed.
- **pplshade** — Requires `PPLShade.exe` + `LECOMAx64.sys` on target. Downloaded during setup.
- **phantomkiller** — Requires `PhantomKiller.exe` + `PhantomKiller.sys` on target. Downloaded during setup.

---

## Environment

Build environment: Windows + WSL2 (Ubuntu). Go builds, MinGW cross-compilation, and all Linux tooling run from WSL2.

Deployment: adpack is a single Go binary — compile once and deploy to any Linux host (Kali, C2 server, attack VM). Pre-built Windows tool binaries are copied alongside.

Tested on DreadGOAD-Light (3 VMware VMs, 2 forests) and VulnAD (Docker).

---

## Configuration

Create `adpack.yaml` in your project directory (or `~/.adpack/config.yaml`):

```yaml
domain: "corp.local"
profile: "undefend"

db_path: ""
nmap_args: ["-T4", "-sn"]
nxc_path: "netexec"
bh_python: "bloodhound-python"

seeds:
  - domain: "corp.local"
    user: "jsmith"
    password: "Password1"

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

Installs Go 1.25+, NetExec, pypykatz, nanodump, PPLShade, PhantomKiller, adpack binary, default config. Clones and builds evasion tool binaries where possible. ~5-10 minutes.

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
