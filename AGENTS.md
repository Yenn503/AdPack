# AdPack — Agent Guide

## What this is

AdPack is a Go-based tool that chains Active Directory and cloud security assessments from seed credentials to full compromise. It tracks everything in an encrypted SQLite DB and figures out what to do next.

Repo: `https://github.com/Yenn503/AdPack`

---

## Quick start for an AI agent

To set up and run AdPack from scratch on a Linux or WSL2 host:

```bash
# 1. Clone and run setup
git clone https://github.com/Yenn503/AdPack.git
cd AdPack
bash setup.sh
source ~/.bashrc

# 2. Create a config with your target domain and seed creds
#    Edit ~/.adpack/config.yaml or create adpack.yaml in the project root:
cat > adpack.yaml << 'EOF'
domain: "corp.local"
profile: "native"
seeds:
  - domain: "corp.local"
    user: "jsmith"
    password: "Password1"
scope:
  - "10.0.0.0/24"
EOF

# 3. Verify it works
adpack status

# 4. Run the full chain
adpack autorun

# Or step through phases manually
adpack run discovery -t 10.0.0.5
adpack run enumeration
adpack run credential_acq
adpack next
```

---

## Pipeline (3 independent tracks)

```
On-prem:  discovery → enumeration → credential_acq → validation/session_harvest/graph_analysis
          → privesc → lateral → persistence → impact

Cloud:    cloud_initial_access → cloud_enum → cloud_cred_acq / cloud_privesc → cloud_pillage

Hybrid:   hybrid_bridge (only connects the above two when both exist)
```

Phases 1–10 are on-prem only. Phases 12–16 are Entra ID only (no on-prem needed). Phase 11 (hybrid bridge) only activates when creds exist on both sides.

---

## Key commands

| What | Command |
|------|---------|
| Run everything | `adpack autorun` |
| Run one phase | `adpack run <phase>` |
| See state | `adpack status` |
| See next step | `adpack next` |
| Reset DB | `rm ~/.adpack/state.db*` then `adpack run discovery` |
| Test creds | `adpack validate` |
| Cloud enumeration | `adpack cloud enum` |
| Teams phishing | `adpack initial teams` |

Available phases: `discovery`, `enumeration`, `credential_acq`, `validation`, `session_harvest`, `graph_analysis`, `privesc`, `lateral`, `persistence`, `impact`, `hybrid_bridge`, `cloud_initial_access`, `cloud_enum`, `cloud_cred_acq`, `cloud_privesc`, `cloud_pillage`.

---

## Config

Minimal `adpack.yaml`:

```yaml
domain: "corp.local"
profile: "native"
seeds:
  - domain: "corp.local"
    user: "jsmith"
    password: "Password1"
scope:
  - "10.0.0.0/24"
```

Config goes in the project root or `~/.adpack/config.yaml`. Scope is a safety net — the tool refuses to touch IPs outside it.

---

## Evasion profiles

Pass with `-e` flag or set in config:

- `native` — default, kills Defender via reg + sc + taskkill
- `pplshade` — BYOVD PPL bypass when LSASS is PPL-protected
- `phantomkiller` — BYOVD EDR process killer

---

## Common issues

- **`adpack: command not found`** after setup — run `source ~/.bashrc` or re-login
- **`netexec: command not found`** — pipx may not be in PATH: `export PATH=$PATH:$HOME/.local/bin`
- **`impacket-getTGT: Name or service not known`** — pass `-dc-ip <DC_IP>` directly or use the tool's built-in DC IP lookup (it handles this automatically from state)
- **DB already exists** — `rm -f ~/.adpack/state.db*` for a clean start
- **WSL2 DNS can't resolve hostnames** — the tool uses IPs from state, not DNS, for LDAP and Kerberos operations

---

## Build & test

```bash
go build -o adpack .
make test        # go test -v -race ./...
make lint        # golangci-lint run ./...
```

---

## Package layout

```
cmd/            — CLI commands
core/           — State, edges, events, sessions
modules/        — Attack modules (one per phase)
tools/          — External tool wrappers (nxc, impacket, etc.)
storage/        — SQLite with AES-256-GCM
planner/        — Privilege path planning
internal/       — BloodHound, hashcat, transport, executor
```

---

## Design

AdPack wraps existing tools (nxc, impacket, nanodump, bloodhound-python) through a transport layer. It doesn't reimplement exploits — it tracks what you know, decides what to try next, and calls the right tool. Commands run locally, through SOCKS5, or through a Sliver C2 implant.
