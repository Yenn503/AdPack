# AdPack Setup Guide

Installation and environment setup for adpack v0.6.0.

## Prerequisites

- Linux (Ubuntu 22.04+, Kali 2024+, Debian 12+) or WSL2
- Internet connection for dependency downloads
- ~2GB disk space for tools and dependencies
- Sudo access for package installation

## Automated Setup

```bash
git clone https://github.com/Yenn503/AdPack.git
cd adpack
./setup.sh
source ~/.bashrc
```

The setup script installs:
- Go 1.25+ (configurable via `GO_VERSION` env var)
- NetExec (nxc) via pipx
- pypykatz for LSASS dump parsing
- nanodump (cross-compiled via MinGW)
- PPLShade + LECOMAx64.sys (BYOVD PPL bypass)
- PhantomKiller + PhantomKiller.sys (BYOVD EDR killer)
- MiniPlasma (pre-built binary download)
- PrintSpoofer64 (pre-built binary download)
- adpack binary built from source
- Default config at `~/.adpack/config.yaml`

Estimated time: 5-10 minutes.

## Custom Go Version

```bash
GO_VERSION=1.25.10 ./setup.sh
```

If the specified version is not available, setup falls back to 1.25.10.

## Manual Installation

### 1. Install Go 1.25+

```bash
wget https://go.dev/dl/go1.25.10.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.10.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
```

### 2. Install System Dependencies

```bash
# Debian/Ubuntu/Kali
sudo apt-get update
sudo apt-get install -y git curl wget build-essential gcc make mingw-w64 \
    python3 python3-pip python3-venv libssl-dev libffi-dev unzip tar gzip \
    mono-complete ldap-utils

# RHEL/Fedora
sudo dnf install -y git curl wget gcc make mingw64-gcc python3 python3-pip \
    openssl-devel libffi-devel unzip tar gzip mono-core openldap-clients

# Arch
sudo pacman -S --noconfirm git curl wget gcc make mingw-w64-gcc python python-pip \
    openssl libffi unzip tar gzip mono openldap
```

### 3. Install Python Tools

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install netexec
pipx install pypykatz
pipx install bloodhound
pipx install certipy-ad
pipx install impacket
pipx install dploot
```

### 4. Build nanodump

```bash
git clone https://github.com/fortra/nanodump.git /tmp/nanodump
cd /tmp/nanodump
x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s
mkdir -p exe && cp nanodump.exe exe/
rm -rf /tmp/nanodump
```

### 5. Download Tool Binaries

```bash
mkdir -p exe

# PrintSpoofer64
wget -q https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe \
    -O exe/PrintSpoofer64.exe

# MiniPlasma
# GitHub repo may be unavailable — see setup.sh for manual install.
# Check adpack docs for alternatives.

# PPLShade + LECOMAx64.sys
wget -q "https://github.com/citronneur/PPLShade/releases/download/v1.0/PPLShade.exe" \
    -O exe/PPLShade.exe
wget -q "https://github.com/citronneur/PPLShade/releases/download/v1.0/LECOMAx64.sys" \
    -O exe/LECOMAx64.sys

# PhantomKiller + PhantomKiller.sys
wget -q "https://github.com/citronneur/PhantomKiller/releases/download/v1.0/PhantomKiller.exe" \
    -O exe/PhantomKiller.exe
wget -q "https://github.com/citronneur/PhantomKiller/releases/download/v1.0/PhantomKiller.sys" \
    -O exe/PhantomKiller.sys
```

### 6. Build adpack

```bash
cd adpack
go mod download
go build -o adpack .
sudo cp adpack /usr/local/bin/
```

### 7. Create Config

```bash
mkdir -p ~/.adpack
chmod 700 ~/.adpack
```

Create `~/.adpack/config.yaml`:

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
    password: "Password1"
    hash: ""

cracking:
  hashcat_path: "/usr/bin/hashcat"
  wordlist: "/usr/share/wordlists/rockyou.txt"
  rules: ["/usr/share/hashcat/rules/best64.rule"]
  timeout_seconds: 600

proxy_address: ""

scope:
  - "10.0.0.0/8"

timing:
  delay_ms: 0
  jitter: 0.0
  max_concurrent: 10

viper:
  enabled: false
  host: "localhost"
  port: 7687
  username: ""
  password: ""
  tls: false
```

## Tool Binary Status

| Binary | Status | Notes |
|--------|--------|-------|
| nanodump.exe | Built during setup | Cross-compiled via MinGW |
| PrintSpoofer64.exe | Downloaded | Pre-built release |
| MiniPlasma.exe | Downloaded | Pre-built release (repo removed — see setup.sh) |
| PPLShade.exe + LECOMAx64.sys | Downloaded | BYOVD PPL bypass |
| PhantomKiller.exe + PhantomKiller.sys | Downloaded | BYOVD process killer |

## Verification

```bash
# Check tool availability
adpack validate tools

# Verify adpack works
adpack status

# Check config
adpack validate config
```

## Directory Structure After Setup

```
~/.adpack/
  config.yaml          # Main configuration
  state.db             # SQLite state database
  sessions/            # Saved engagement sessions

~/tools/               # External tools directory

adpack/
  exe/                 # Windows tool binaries
    nanodump.exe
    PrintSpoofer64.exe
    MiniPlasma.exe     # (optional — see setup.sh)
    PPLShade.exe
    LECOMAx64.sys
    PhantomKiller.exe
    PhantomKiller.sys
```

## Troubleshooting

### Go version too old
Set `GO_VERSION=1.25.10` before running setup.sh, or install Go manually.

### pipx commands not found
```bash
source ~/.bashrc
export PATH=$PATH:$HOME/.local/bin
```

### MinGW not available (nanodump build fails)
Install mingw-w64: `sudo apt-get install mingw-w64`
Or skip — adpack falls back to other credential acquisition methods.

### MiniPlasma not available
MiniPlasma GitHub repo may be unavailable. See setup.sh for graceful fallback and manual install instructions. adpack continues without it.

### Permission denied on ~/.adpack
```bash
chmod 700 ~/.adpack
chmod 600 ~/.adpack/config.yaml
```

## Platform Notes

- **Primary target**: Linux (Kali, Ubuntu) or WSL2
- **Windows binaries**: Cross-compiled via MinGW during setup
- **macOS**: Not tested; may work with Homebrew equivalents
- **Docker**: Not officially supported; bind-mount tools directory
