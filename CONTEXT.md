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

## Phase Dependencies
```
discovery → enumeration → credential_acq → session_harvest → lateral
                        → graph_analysis  → privesc        → persistence
                        → validation
```

## Evasion Profiles
11 profiles: minimal, standard, aggressive, bof, fork, byovd, coldwer, undefend, bluehammer, phantomkiller, miniplasma
Each selects delivery (donut/bof/exe) + optional pre-conditions (Defender kill, EDR freeze, kernel driver).

## Tool Ecosystem
| Tool | Role |
|------|------|
| NetExec (nxc) | SMB/WMI/WinRM remote execution, file transfer, auth testing |
| Donut | PE-to-shellcode conversion for in-memory execution |
| nanodump | LSASS minidump with evasion techniques (fork, snapshot, WER) |
| go-mimikatz | Go port of mimikatz for sekurlsa::logonpasswords, dcsync |
| SysWhispers4 | Direct syscall generation for Nt* API evasion |
| ScareCrow | Signed loader DLL generation for shellcode |
| pypykatz | Offline LSASS dump parsing |
| UnDefend | Defender DOS — passive (block updates) or aggressive (kill) |
| BlueHammer | Defender RPC exploit for SAM hive leak via VSS |
| EDR-Freeze | WerFaultSecure PPL bypass to freeze EDR processes |
