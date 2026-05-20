# adpack Setup Guide

Install guide for adpack.

## Quick Start (Automated)

Run `./setup.sh` to install:

```bash
# Clone repository
git clone https://github.com/yourusername/adpack.git
cd adpack

# Run setup script
chmod +x setup.sh
./setup.sh

# Reload shell
source ~/.bashrc

# Verify installation
adpack status
```

Setup.sh is best-effort; tool availability is environment-dependent and tiered. Cross-compilable tools (UnDefend) are built from source, release-binary tools (PhantomKiller, MiniPlasma) are downloaded as artifacts, and Windows-native tools (BlueHammer) require manual build on Windows.

Setup script installs core tools and creates placeholders:
- ✅ System dependencies (gcc, make, mingw, python3)
- ✅ Go 1.25+ installation
- ✅ NetExec (nxc) via pipx
- ✅ Donut (PE-to-shellcode converter)
- ✅ go-mimikatz (cred extraction)
- ✅ pypykatz (dump parsing)
- ✅ ScareCrow (loader generation)
- ✅ nanodump (LSASS dumping, cross-compiled)
- ✅ adpack binary build and installation
- ✅ Default configuration file
- ✅ PATH configuration
- ✅ Verification tests
- ⚠️ Placeholders for evasion tool binaries (UnDefend, BlueHammer, etc.)

**Time:** ~5-10 min

## Table of Contents

- [Quick Start (Automated)](#quick-start-automated)
- [Manual Installation](#manual-installation)
- [System Requirements](#system-requirements)
- [Core Dependencies](#core-dependencies)
- [Optional Tools](#optional-tools)
- [Evasion Tools](#evasion-tools)
- [Environment Setup](#environment-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Manual Installation

Manual install if setup script fails.

## System Requirements

- **OS**: Linux (Ubuntu 22.04+, Kali Linux, Parrot OS) or WSL2
- **Architecture**: x86_64 (amd64)
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 10GB free space
- **Network**: Access to target AD environment

## Core Dependencies

### Go 1.25+

```bash
# Download and install Go
wget https://go.dev/dl/go1.25.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.10.linux-amd64.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

### NetExec

Main tool for remote exec and enum.

```bash
# Install pipx if not already installed
sudo apt update
sudo apt install -y pipx
pipx ensurepath

# Install NetExec
pipx install netexec

# Verify installation
netexec --version
```

### Build adpack

```bash
# Clone repository
git clone https://github.com/yourusername/adpack.git
cd adpack

# Build binary
go build -o adpack .

# Install system-wide (optional)
sudo mv adpack /usr/local/bin/

# Verify installation
adpack version
adpack status
```

## Optional Tools

Tools for evasion and cred extraction.

### Donut

PE-to-shellcode converter for in-memory execution.

```bash
# Install dependencies
sudo apt install -y git make gcc

# Clone and build Donut
git clone https://github.com/TheWover/donut.git
cd donut
make

# Install binary
sudo cp donut /usr/local/bin/

# Verify installation
donut --help
```

### nanodump

LSASS dumping with evasion.

```bash
# Clone repository
git clone https://github.com/fortra/nanodump.git
cd nanodump

# Build with MinGW (cross-compile for Windows)
sudo apt install -y mingw-w64
x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s

# Move to tools directory
mkdir -p ~/tools
cp nanodump.exe ~/tools/

# Add to PATH
echo 'export PATH=$PATH:$HOME/tools' >> ~/.bashrc
source ~/.bashrc
```

### go-mimikatz

Go port of mimikatz for cred extraction.

```bash
# Clone repository
git clone https://github.com/vyrus001/go-mimikatz.git
cd go-mimikatz

# Build binary
go build -o go-mimikatz main.go

# Install binary
sudo cp go-mimikatz /usr/local/bin/

# Verify installation
go-mimikatz --help
```

### pypykatz

Offline LSASS dump parsing.

```bash
# Install via pip
pip3 install pypykatz

# Or via pipx (isolated environment)
pipx install pypykatz

# Verify installation
pypykatz --help
```

## Evasion Tools

Advanced evasion tools require separate acquisition. The setup script creates placeholders.

### ScareCrow

Signed loader DLL generation for shellcode (installed by setup.sh).

```bash
# Clone repository
git clone https://github.com/optiv/ScareCrow.git
cd ScareCrow

# Build binary
go build -o ScareCrow main.go

# Install binary
sudo cp ScareCrow /usr/local/bin/

# Verify installation
ScareCrow --help
```

### UnDefend

Windows Defender termination tool. Cross-compiled binary available at `~/tools/UnDefend.exe` after running setup.

```bash
# Verify
ls -lh ~/tools/UnDefend.exe
```

### BlueHammer (FunnyApp)

CVE-2026-33825 Defender RPC exploit for SAM extraction.

**Note**: BlueHammer's 3313-line MSVC project (`FunnyApp.cpp`) cannot be cross-compiled with MinGW (requires `cfapi.h`, RPC IDL, Windows Update Agent COM). Must be built natively on Windows with Visual Studio 2022 via `FunnyApp.sln`. No public GitHub release. Setup.sh creates a placeholder.

```bash
# Setup.sh creates a placeholder at ~/tools/FunnyApp.exe
# Replace with actual exploit binary built on Windows in Visual Studio

# Verify
ls -lh ~/tools/FunnyApp.exe
```

### PhantomKiller

BYOVD EDR killer using Lenovo BootRepair.sys. Pre-built binary + driver available at `~/tools/PhantomKiller.exe` and `~/tools/PhantomKiller.sys` after running setup.

```bash
# Verify
ls -lh ~/tools/PhantomKiller.exe ~/tools/PhantomKiller.sys
```

### MiniPlasma

Cloud Filter API EoP (CVE-2020-17103) for SYSTEM shell. Built binary + runtime DLLs available at `~/tools/MiniPlasma.exe`, `~/tools/NtApiDotNet.dll`, and `~/tools/Microsoft.Win32.TaskScheduler.dll` after running setup.

```bash
# Verify
ls -lh ~/tools/MiniPlasma.exe ~/tools/NtApiDotNet.dll ~/tools/Microsoft.Win32.TaskScheduler.dll
```

## Environment Setup

### Directory Structure

```bash
# Create adpack directories
mkdir -p ~/.adpack
mkdir -p ~/tools

# Set permissions
chmod 700 ~/.adpack
chmod 755 ~/tools
```

### Configuration

Create `~/.adpack/config.yaml`:

```yaml
db_path: "~/.adpack/state.db"

nxc_path: "netexec"
bh_python: "bloodhound-python"

viper:
  enabled: false
  host: "localhost"
  port: 7687
```

### PATH Configuration

Ensure all tools are in PATH:

```bash
# Add to ~/.bashrc
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/tools' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc

# Reload
source ~/.bashrc
```

## Verification

### Check Core Tools

```bash
# Go
go version

# NetExec
netexec --version

# adpack
adpack version
adpack status
```

### Check Optional Tools

```bash
# Donut
donut --help

# go-mimikatz
go-mimikatz --help

# pypykatz
pypykatz --help

# nanodump (Windows binary, check existence)
ls -lh ~/tools/nanodump.exe
```

### Check Evasion Tools

```bash
# ScareCrow
ScareCrow --help

# UnDefend (Windows binary)
ls -lh ~/tools/UnDefend.exe

# BlueHammer/FunnyApp (Windows binary — requires MSVC build)
ls -lh ~/tools/FunnyApp.exe

# PhantomKiller BYOVD (Windows binary + driver)
ls -lh ~/tools/PhantomKiller.exe ~/tools/PhantomKiller.sys

# MiniPlasma (Windows binary + DLL deps)
ls -lh ~/tools/MiniPlasma.exe ~/tools/NtApiDotNet.dll ~/tools/Microsoft.Win32.TaskScheduler.dll
```

### Test adpack

```bash
# Initialise database
adpack status

# Check available profiles
adpack profiles

# List phases
adpack phases
```

## Troubleshooting

### Go Not Found

```bash
# Verify Go installation
which go

# If not found, check PATH
echo $PATH

# Re-add to PATH
export PATH=$PATH:/usr/local/go/bin
source ~/.bashrc
```

### NetExec Not Found

```bash
# Verify pipx installation
pipx list

# Reinstall NetExec
pipx uninstall netexec
pipx install netexec

# Check PATH
which netexec
```

### adpack Build Fails

```bash
# Clean and rebuild
cd adpack
go clean
go mod tidy
go build -o adpack .

# Check for missing dependencies
go mod download
```

### Tool Not Available

```bash
# Check if tool is in PATH
which <tool_name>

# Check tool permissions
ls -lh /usr/local/bin/<tool_name>

# Make executable if needed
chmod +x /usr/local/bin/<tool_name>
```

### Database Errors

```bash
# Reset database
adpack reset state

# Check database permissions
ls -lh ~/.adpack/state.db
chmod 600 ~/.adpack/state.db

# Recreate database
rm ~/.adpack/state.db
adpack status
```

### Windows Binary Execution in WSL

```bash
# Ensure WSL can execute Windows binaries
# Check if binfmt_misc is enabled
cat /proc/sys/fs/binfmt_misc/status

# If disabled, enable it
sudo update-binfmts --enable

# Test Windows binary execution
cmd.exe /c echo "Test"
```

## Lab Setup

### VulnAD (Docker)

```bash
# Pull and run VulnAD container
docker pull vulnerables/vulnad
docker run -d -p 389:389 -p 445:445 -p 88:88 --name vulnad vulnerables/vulnad

# Get container IP
docker inspect vulnad | grep IPAddress

# Test with adpack
adpack run discovery --target <container_ip>
```

### GOAD (Vagrant)

```bash
# Clone GOAD repository
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD

# Install Vagrant and VirtualBox
sudo apt install -y vagrant virtualbox

# Provision GOAD lab
cd ad/GOAD/providers/virtualbox
vagrant up

# Get DC IP from Vagrant
vagrant ssh dc01 -c "ipconfig"

# Test with adpack
adpack run discovery --target <dc_ip>
```

## Security Considerations

- Only use on authorised targets with explicit written permission
- Protect tool binaries with appropriate permissions (chmod 700)
- **Credentials are stored in plaintext** — Protect `~/.adpack/state.db` with file permissions (600) and disk encryption
- Clean up after engagements: `adpack reset state`
- Follow responsible disclosure for vulnerabilities found
- Advanced evasion techniques should be used responsibly and legally
- Acquire exploit binaries through legitimate channels only

## Next Steps

1. Complete tool installation
2. Configure `~/.adpack/config.yaml`
3. Set up vulnerable AD lab (VulnAD or GOAD)
4. Run `adpack status` to verify setup
5. Test with `adpack autorun --target <lab_ip>`
6. Review [USAGE.md](USAGE.md) for workflows

## Support

For issues or questions:
- Check [USAGE.md](USAGE.md) for command reference
- Review [CONTEXT.md](CONTEXT.md) for architecture details
- Open an issue on GitHub
- Consult [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
