# adpack Setup Guide

## Quick Start (Automated)

```bash
git clone https://github.com/Yenn503/AdPack.git
cd AdPack
chmod +x setup.sh
./setup.sh
source ~/.bashrc
adpack status
```

Setup.sh is best-effort; tool availability is environment-dependent. Cross-compilable tools (UnDefend) are built from source, and release-binary tools (PhantomKiller) are downloaded as artifacts.

Setup installs:
- System dependencies (gcc, make, mingw, python3)
- Go 1.25+
- NetExec (nxc) via pipx
- Donut (PE-to-shellcode converter)
- pypykatz (dump parsing)
- ScareCrow (loader generation)
- nanodump (LSASS dumping, cross-compiled)
- adpack binary build and installation
- Default configuration file
- PATH configuration
- Verification tests
- Placeholders for evasion tool binaries (UnDefend, BlueHammer, etc.)

**Time:** ~5-10 min

## Manual Installation

### System Requirements

- **OS**: Linux (Ubuntu 22.04+, Kali Linux, Parrot OS) or WSL2
- **Architecture**: x86_64 (amd64)
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 10GB free space
- **Network**: Access to target AD environment

### Core Dependencies

#### Go 1.25+

```bash
wget https://go.dev/dl/go1.25.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.10.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

#### NetExec

```bash
sudo apt update && sudo apt install -y pipx
pipx ensurepath
pipx install netexec
netexec --version
```

#### Build adpack

```bash
git clone https://github.com/Yenn503/AdPack.git
cd AdPack
go build -o adpack .
sudo mv adpack /usr/local/bin/
adpack version
adpack status
```

### Optional Tools

#### Donut

PE-to-shellcode converter.

```bash
sudo apt install -y git make gcc
git clone https://github.com/TheWover/donut.git
cd donut && make && sudo cp donut /usr/local/bin/
```

#### nanodump

LSASS dumping with evasion.

```bash
sudo apt install -y mingw-w64
git clone https://github.com/fortra/nanodump.git
cd nanodump
x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s
mkdir -p ~/tools && cp nanodump.exe ~/tools/
echo 'export PATH=$PATH:$HOME/tools' >> ~/.bashrc
```

#### go-mimikatz

```bash
git clone https://github.com/vyrus001/go-mimikatz.git
cd go-mimikatz && go build -o go-mimikatz main.go
sudo cp go-mimikatz /usr/local/bin/
```

#### pypykatz

```bash
pip3 install pypykatz
# or: pipx install pypykatz
```

#### hashcat (for the cracking pipeline)

```bash
sudo apt install -y hashcat
# Or download from https://hashcat.net/hashcat/
```

### Evasion Tools

#### ScareCrow

```bash
git clone https://github.com/optiv/ScareCrow.git
cd ScareCrow && go build -o ScareCrow main.go
sudo cp ScareCrow /usr/local/bin/
```

#### UnDefend

Cross-compiled from source during setup. Verify:

```bash
ls -lh ~/tools/UnDefend.exe
```

#### BlueHammer (FunnyApp)

CVE-2026-33825 Defender RPC exploit. Requires Visual Studio 2022 on Windows — cannot be cross-compiled. Setup.sh creates a placeholder.

```bash
ls -lh ~/tools/FunnyApp.exe
```

#### PhantomKiller

Pre-built release downloaded during setup.

```bash
ls -lh ~/tools/PhantomKiller.exe ~/tools/PhantomKiller.sys
```

#### MiniPlasma

Pre-built release downloaded during setup.

```bash
ls -lh ~/tools/MiniPlasma.exe ~/tools/NtApiDotNet.dll ~/tools/Microsoft.Win32.TaskScheduler.dll
```

### Configuration

Create `~/.adpack/config.yaml`:

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
```

### Directory Structure

```bash
mkdir -p ~/.adpack ~/tools
chmod 700 ~/.adpack
chmod 755 ~/tools
```

### PATH Configuration

```bash
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/tools' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc
```

### Verification

```bash
go version
netexec --version
adpack version
adpack status
```

Optional tools:

```bash
donut --help
go-mimikatz --help
pypykatz --help
ls -lh ~/tools/nanodump.exe
hashcat --version
```

Evasion tools:

```bash
ls -lh ~/tools/UnDefend.exe ~/tools/FunnyApp.exe
ls -lh ~/tools/PhantomKiller.exe ~/tools/PhantomKiller.sys
ls -lh ~/tools/MiniPlasma.exe ~/tools/NtApiDotNet.dll ~/tools/Microsoft.Win32.TaskScheduler.dll
```

## Lab Setup

### VulnAD (Docker)

```bash
docker pull vulnerables/vulnad
docker run -d -p 389:389 -p 445:445 -p 88:88 --name vulnad vulnerables/vulnad
docker inspect vulnad | grep IPAddress
adpack run discovery --target <container_ip>
```

### GOAD (Vagrant)

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
sudo apt install -y vagrant virtualbox
cd ad/GOAD/providers/virtualbox
vagrant up
adpack run discovery --target <dc_ip>
```

## Security Considerations

- Only use on authorised targets with explicit written permission
- Credentials are encrypted at rest with AES-GCM. Protect the database and key files.
- Clean up after engagements: `adpack reset state`
- Use scope enforcement in config to prevent accidental targeting
- Follow responsible disclosure for vulnerabilities found

## Next Steps

1. Complete tool installation
2. Configure `~/.adpack/config.yaml`
3. Set up a vulnerable AD lab (VulnAD or GOAD)
4. Run `adpack status` to verify
5. Test with `adpack autorun --target <lab_ip>`
6. Review [USAGE.md](USAGE.md) for workflows
