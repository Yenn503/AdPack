# AdPack Setup Guide

Installation and environment setup for adpack v0.4.0.

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
- Donut shellcode generator
- pypykatz for LSASS dump parsing
- nanodump (cross-compiled via MinGW)
- ScareCrow for AV evasion
- MiniPlasma (pre-built binary download)
- PrintSpoofer64 (pre-built binary download)
- UnDefend (from repo root if available)
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

### 4. Install Donut

```bash
git clone https://github.com/TheWover/donut.git /tmp/donut
cd /tmp/donut && make
sudo cp donut /usr/local/bin/
rm -rf /tmp/donut
```

### 5. Build nanodump

```bash
git clone https://github.com/fortra/nanodump.git /tmp/nanodump
cd /tmp/nanodump
x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s
mkdir -p exe && cp nanodump.exe exe/
rm -rf /tmp/nanodump
```

### 6. Download Tool Binaries

```bash
mkdir -p exe

# PrintSpoofer64
wget -q https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe \
    -O exe/PrintSpoofer64.exe

# MiniPlasma
wget -q "https://github.com/Nightmare-Eclipse/MiniPlasma/releases/download/main-release/PoC_AbortHydration_ArbitraryRegKey_EoP.exe" \
    -O exe/MiniPlasma.exe

# go-mimikatz (requires Windows build)
# Build on Windows: cd go-mimikatz && go generate && go build -o go-mimikatz.exe .
# Then copy go-mimikatz.exe to exe/
```

### 7. Build adpack

```bash
cd adpack
go mod download
go build -o adpack .
sudo cp adpack /usr/local/bin/
```

### 8. Create Config

```bash
mkdir -p ~/.adpack
chmod 700 ~/.adpack
```

Create `~/.adpack/config.yaml`:

```yaml
db_path: "/home/user/.adpack/state.db"

nxc_path: "netexec"
bh_python: "bloodhound-python"
certipy_path: "certipy"
impacket_dir: "/usr/share/doc/python3-impacket/examples"

cracking:
  hashcat_path: "hashcat"
  wordlist: "/usr/share/wordlists/rockyou.txt"
  rules: []
  timeout: 300

proxy_address: ""

viper:
  enabled: false
  host: "localhost"
  port: 7687

evasion:
  default_profile: "standard"
  auto_av_kill: true
```

## Tool Binary Status

| Binary | Status | Notes |
|--------|--------|-------|
| nanodump.exe | Built during setup | Cross-compiled via MinGW |
| go-mimikatz.exe | Windows build required | Falls back to nanodump+pypykatz |
| PrintSpoofer64.exe | Downloaded | Pre-built release |
| MiniPlasma.exe | Downloaded | Pre-built release |
| UnDefend.exe | Copied from repo | Private tool, place in exe/ |

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
    go-mimikatz.exe    # (optional, Windows build)
    PrintSpoofer64.exe
    MiniPlasma.exe
    UnDefend.exe       # (optional, private)
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

### go-mimikatz not available
This is expected on Linux. adpack automatically falls back to nanodump + pypykatz for credential extraction. Build go-mimikatz on Windows if needed.

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
