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

Setup script installs everything:
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
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz

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
go build -o adpack main.go

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

Tools for bypassing endpoint protection.

### ScareCrow

Signed loader DLL generation for shellcode.

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

Windows Defender termination tool.

**Note**: UnDefend.exe is a Windows binary. Build on Windows or use pre-compiled binary.

```bash
# Clone repository (on Windows or WSL with Windows filesystem access)
git clone https://github.com/APTortellini/unDefend.git
cd unDefend

# Build on Windows with Visual Studio or MinGW
# Or download pre-compiled binary from releases

# Copy to tools directory
mkdir -p ~/tools
cp UnDefend.exe ~/tools/
```

### BlueHammer (FunnyApp)

CVE-2026-33825 Defender RPC exploit for SAM extraction.

**Note**: This is a fictional zero-day for demonstration. Replace with actual exploit if available.

```bash
# Placeholder for BlueHammer/FunnyApp
# In production, this would be a custom exploit or tool
# For testing, create a dummy binary

mkdir -p ~/tools
echo '#!/bin/bash' > ~/tools/FunnyApp.exe
echo 'echo "[*] BlueHammer exploit executed (placeholder)"' >> ~/tools/FunnyApp.exe
chmod +x ~/tools/FunnyApp.exe
```

### EDR-Freeze (ColdWer)

EDR process freezing tool.

**Note**: EDR-Freeze is a Windows binary. Build on Windows or use pre-compiled binary.

```bash
# Clone repository (if available)
# git clone https://github.com/example/edr-freeze.git
# cd edr-freeze

# Build on Windows with Visual Studio or MinGW
# Or download pre-compiled binary

# Copy to tools directory
mkdir -p ~/tools
# cp EDR-Freeze.exe ~/tools/
```

### RTCore64.sys

Vulnerable driver for BYOVD (Bring Your Own Vulnerable Driver) attacks.

**Note**: RTCore64.sys is a signed vulnerable driver from MSI Afterburner.

```bash
# Download from public sources or extract from MSI Afterburner
# https://www.msi.com/Landing/afterburner

# Copy to tools directory
mkdir -p ~/tools
# cp RTCore64.sys ~/tools/
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
# Database location
db_path: "~/.adpack/state.db"

# Target defaults
target:
  domain: ""
  dc_ip: ""
  username: ""
  password: ""

# Tool paths
tools:
  netexec: "netexec"
  donut: "donut"
  nanodump: "~/tools/nanodump.exe"
  gomimikatz: "go-mimikatz"
  pypykatz: "pypykatz"
  scarecrow: "ScareCrow"
  undefend: "~/tools/UnDefend.exe"
  bluehammer: "~/tools/FunnyApp.exe"
  edrfreeze: "~/tools/EDR-Freeze.exe"
  rtcore: "~/tools/RTCore64.sys"

# Evasion settings
evasion:
  default_profile: "standard"
  command_timeout: 120
  retry_on_failure: false
  max_retries: 3

# Output settings
output:
  verbose: false
  save_raw_output: true
  raw_output_dir: "./output"
  json_output: false

# Phase settings
phases:
  skip_completed: true
  auto_advance: false
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

# BlueHammer/FunnyApp (Windows binary)
ls -lh ~/tools/FunnyApp.exe

# EDR-Freeze (Windows binary)
ls -lh ~/tools/EDR-Freeze.exe

# RTCore64.sys (driver)
ls -lh ~/tools/RTCore64.sys
```

### Test adpack

```bash
# Initialize database
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
go build -o adpack main.go

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

- Only use on authorised targets
- Protect tool binaries with appropriate permissions
- Store creds securely
- Clean up after engagements: `adpack reset state`
- Follow responsible disclosure for vulnerabilities found
- Zero-day exploits should be used responsibly

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
