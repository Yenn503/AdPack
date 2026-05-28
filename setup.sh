#!/usr/bin/env bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
TOOLS_DIR="$HOME/tools"
ADPACK_DIR="$HOME/.adpack"
INSTALL_DIR="/usr/local/bin"

# Logging
LOG_FILE="$HOME/adpack_setup.log"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  adpack Setup Script                      ║${NC}"
echo -e "${BLUE}║          Automated installation of all dependencies       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Success message
success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log "SUCCESS: $1"
}

# Info message
info() {
    echo -e "${BLUE}[*]${NC} $1"
    log "INFO: $1"
}

# Warning message
warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARNING: $1"
}

# Error message
error() {
    echo -e "${RED}[✗]${NC} $1"
    log "ERROR: $1"
}

# Check if running on Linux or WSL
check_os() {
    info "Checking operating system..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        success "Running on Linux"
        return 0
    elif grep -qi microsoft /proc/version 2>/dev/null; then
        success "Running on WSL"
        return 0
    else
        error "This script requires Linux or WSL"
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. This is not recommended."
        echo -n "Continue anyway? (y/N): "
        read -r REPLY
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Create directories
create_dirs() {
    info "Creating directories..."
    mkdir -p "$TOOLS_DIR"
    mkdir -p "$ADPACK_DIR"
    mkdir -p "$HOME/.local/bin"
    chmod 700 "$ADPACK_DIR"
    success "Directories created"
}

# Install system dependencies
install_system_deps() {
    info "Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y \
            git curl wget build-essential \
            gcc make mingw-w64 \
            python3 python3-pip python3-venv \
            libssl-dev libffi-dev \
            unzip tar gzip \
            mono-complete &>> "$LOG_FILE"
        success "System dependencies installed"
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            git curl wget gcc make \
            mingw64-gcc python3 python3-pip \
            openssl-devel libffi-devel \
            unzip tar gzip \
            mono-core &>> "$LOG_FILE"
        success "System dependencies installed"
    else
        warn "Unknown package manager. Please install dependencies manually."
    fi
}

# Install Go
install_go() {
    info "Checking Go installation..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        if [[ "$GO_VERSION" > "1.25" ]] || [[ "$GO_VERSION" == "1.25"* ]]; then
            success "Go $GO_VERSION already installed"
            return 0
        else
            warn "Go version $GO_VERSION is too old. Installing Go 1.25..."
        fi
    fi
    
    info "Installing Go 1.25.10..."
    cd /tmp
    wget -q https://go.dev/dl/go1.25.10.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.25.10.linux-amd64.tar.gz
    rm go1.25.10.linux-amd64.tar.gz
    
    # Add to PATH if not already there
    if ! grep -q "/usr/local/go/bin" "$HOME/.bashrc"; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
        echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:$HOME/go/bin
    
    success "Go 1.25.10 installed"
}

# Install pipx
install_pipx() {
    info "Checking pipx installation..."
    
    if command -v pipx &> /dev/null; then
        success "pipx already installed"
        return 0
    fi
    
    info "Installing pipx..."
    python3 -m pip install --user pipx &>> "$LOG_FILE"
    python3 -m pipx ensurepath &>> "$LOG_FILE"
    
    export PATH=$PATH:$HOME/.local/bin
    
    success "pipx installed"
}

# Install NetExec
install_netexec() {
    info "Checking NetExec installation..."
    
    if command -v netexec &> /dev/null || command -v nxc &> /dev/null; then
        success "NetExec already installed"
        return 0
    fi
    
    info "Installing NetExec..."
    pipx install netexec &>> "$LOG_FILE"
    
    success "NetExec installed"
}

# Install Donut
install_donut() {
    info "Checking Donut installation..."
    
    if command -v donut &> /dev/null; then
        success "Donut already installed"
        return 0
    fi
    
    info "Installing Donut..."
    cd /tmp
    git clone https://github.com/TheWover/donut.git &>> "$LOG_FILE"
    cd donut
    make &>> "$LOG_FILE"
    sudo cp donut /usr/local/bin/
    cd /tmp
    rm -rf donut
    
    success "Donut installed"
}

# Install nanodump
install_nanodump() {
    local repo_root
    repo_root="$(cd "$(dirname "$0")" && pwd)"
    local exe_dir="$repo_root/exe"
    mkdir -p "$exe_dir"
    
    info "Checking nanodump installation..."
    
    if [[ -f "$exe_dir/nanodump.exe" ]]; then
        success "nanodump already installed in exe/"
        return 0
    fi
    
    info "Building nanodump..."
    cd /tmp
    git clone https://github.com/fortra/nanodump.git &>> "$LOG_FILE"
    cd nanodump
    
    # Build with MinGW
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s &>> "$LOG_FILE"
        cp nanodump.exe "$exe_dir/"
        success "nanodump built and installed to exe/"
    else
        warn "MinGW not available. Skipping nanodump build."
        warn "You can build it manually on Windows or download a pre-compiled binary."
    fi
    
    cd /tmp
    rm -rf nanodump
}

# Install go-mimikatz
install_gomimikatz() {
    local repo_root
    repo_root="$(cd "$(dirname "$0")" && pwd)"
    local exe_dir="$repo_root/exe"
    mkdir -p "$exe_dir"
    
    info "Checking go-mimikatz installation..."
    
    # Linux binary for local execution
    if ! command -v go-mimikatz &> /dev/null; then
        info "Building go-mimikatz (Linux binary for local use)..."
        cd /tmp
        git clone https://github.com/vyrus001/go-mimikatz.git &>> "$LOG_FILE"
        cd go-mimikatz
        go build -o go-mimikatz main.go &>> "$LOG_FILE"
        sudo cp go-mimikatz /usr/local/bin/
        cd /tmp
        rm -rf go-mimikatz
        success "go-mimikatz (Linux) installed to /usr/local/bin/"
    else
        info "go-mimikatz (Linux) already on PATH"
    fi
    
    # Windows PE for remote SMB deployment
    if [[ ! -f "$exe_dir/go-mimikatz.exe" ]]; then
        info "Cross-compiling go-mimikatz.exe (Windows PE for SMB deploy)..."
        cd /tmp
        if [[ ! -d go-mimikatz ]]; then
            git clone https://github.com/vyrus001/go-mimikatz.git &>> "$LOG_FILE"
        fi
        cd go-mimikatz
        GOOS=windows GOARCH=amd64 go build -o go-mimikatz.exe main.go &>> "$LOG_FILE"
        cp go-mimikatz.exe "$exe_dir/"
        cd /tmp
        rm -rf go-mimikatz
        success "go-mimikatz.exe built and installed to exe/"
    else
        info "go-mimikatz.exe already in exe/"
    fi
}

# Install pypykatz
install_pypykatz() {
    info "Checking pypykatz installation..."
    
    if command -v pypykatz &> /dev/null; then
        success "pypykatz already installed"
        return 0
    fi
    
    info "Installing pypykatz..."
    pipx install pypykatz &>> "$LOG_FILE"
    
    success "pypykatz installed"
}

# Install ScareCrow
install_scarecrow() {
    info "Checking ScareCrow installation..."
    
    if command -v ScareCrow &> /dev/null; then
        success "ScareCrow already installed"
        return 0
    fi
    
    info "Building ScareCrow..."
    cd /tmp
    git clone https://github.com/optiv/ScareCrow.git &>> "$LOG_FILE"
    cd ScareCrow
    go build -o ScareCrow main.go &>> "$LOG_FILE"
    sudo cp ScareCrow /usr/local/bin/
    cd /tmp
    rm -rf ScareCrow
    
    success "ScareCrow installed"
}

# Install SweetPotato
install_sweetpotato() {
    local repo_root
    repo_root="$(cd "$(dirname "$0")" && pwd)"
    local exe_dir="$repo_root/exe"
    mkdir -p "$exe_dir"
    
    info "Checking SweetPotato installation..."
    
    if [[ -f "$exe_dir/SweetPotato.exe" ]]; then
        success "SweetPotato already installed in exe/"
        return 0
    fi
    
    info "Building SweetPotato..."
    cd /tmp
    git clone https://github.com/CCob/SweetPotato.git &>> "$LOG_FILE"
    cd SweetPotato
    
    # Build with msbuild if available, otherwise download release
    if command -v msbuild &> /dev/null || command -v xbuild &> /dev/null; then
        if command -v msbuild &> /dev/null; then
            msbuild SweetPotato.sln /p:Configuration=Release &>> "$LOG_FILE"
            cp bin/Release/SweetPotato.exe "$exe_dir/" 2>/dev/null || true
        fi
    fi
    
    # If build failed or not available, download from releases
    if [[ ! -f "$exe_dir/SweetPotato.exe" ]]; then
        info "Downloading SweetPotato from releases..."
        wget -q https://github.com/CCob/SweetPotato/releases/latest/download/SweetPotato.exe -O "$exe_dir/SweetPotato.exe" 2>/dev/null || \
        warn "Could not download SweetPotato. You may need to build it manually on Windows."
    fi
    
    cd /tmp
    rm -rf SweetPotato
    
    if [[ -f "$exe_dir/SweetPotato.exe" ]]; then
        success "SweetPotato installed in exe/"
    else
        warn "SweetPotato not installed. Build manually if needed."
    fi
}

# Install MiniPlasma
install_miniplasma() {
    local repo_root
    repo_root="$(cd "$(dirname "$0")" && pwd)"
    local exe_dir="$repo_root/exe"
    mkdir -p "$exe_dir"
    
    info "Checking MiniPlasma installation..."
    
    if [[ -f "$exe_dir/MiniPlasma.exe" ]]; then
        success "MiniPlasma already installed in exe/"
        return 0
    fi
    
    info "Downloading MiniPlasma from GitHub release..."
    cd /tmp
    
    wget -q "https://github.com/Nightmare-Eclipse/MiniPlasma/releases/download/main-release/PoC_AbortHydration_ArbitraryRegKey_EoP.exe" \
        -O MiniPlasma.exe &>> "$LOG_FILE"
    
    if [[ -f "MiniPlasma.exe" ]] && [[ -s "MiniPlasma.exe" ]]; then
        cp MiniPlasma.exe "$exe_dir/"
    else
        # Fallback: try building from source with mcs
        info "Release download failed, attempting build from source..."
        if git clone https://github.com/Nightmare-Eclipse/MiniPlasma.git &>> "$LOG_FILE"; then
            cd MiniPlasma/PoC_AbortHydration_ArbitraryRegKey_EoP
            if command -v mcs &> /dev/null; then
                mcs -out:MiniPlasma.exe -reference:System.ServiceProcess.dll \
                    Program.cs &>> "$LOG_FILE" && \
                cp MiniPlasma.exe "$exe_dir/" 2>/dev/null || true
            fi
            cd /tmp
            rm -rf MiniPlasma
        else
            warn "Could not clone MiniPlasma."
        fi
    fi
    
    rm -f /tmp/MiniPlasma.exe
    
    if [[ -f "$exe_dir/MiniPlasma.exe" ]]; then
        success "MiniPlasma installed in exe/ ($(ls -lh "$exe_dir/MiniPlasma.exe" | awk '{print $5}'))"
    else
        warn "MiniPlasma not installed. Download from GitHub releases or build with .NET."
    fi
}

# Build adpack
build_adpack() {
    info "Building adpack..."
    
    if [[ ! -f "go.mod" ]]; then
        error "go.mod not found. Are you in the adpack directory?"
        exit 1
    fi
    
    go mod download &>> "$LOG_FILE"
    go build -o adpack . &>> "$LOG_FILE"
    
    if [[ -f "adpack" ]]; then
        sudo cp adpack /usr/local/bin/
        success "adpack built and installed to /usr/local/bin/adpack"
    else
        error "Failed to build adpack"
        exit 1
    fi
}

# Create default config
create_config() {
    info "Creating default configuration..."
    
    if [[ -f "$ADPACK_DIR/config.yaml" ]]; then
        warn "Config already exists at $ADPACK_DIR/config.yaml"
        return 0
    fi
    
    cat > "$ADPACK_DIR/config.yaml" << EOF
# adpack configuration
db_path: "$ADPACK_DIR/state.db"

nxc_path: "netexec"
bh_python: "bloodhound-python"

viper:
  enabled: false
  host: "localhost"
  port: 7687
EOF
    
    success "Configuration created at $ADPACK_DIR/config.yaml"
}

# Update PATH in shell config
update_path() {
    info "Updating PATH in shell configuration..."
    
    local repo_root
    repo_root="$(cd "$(dirname "$0")" && pwd)"
    
    SHELL_RC="$HOME/.bashrc"
    if [[ -f "$HOME/.zshrc" ]]; then
        SHELL_RC="$HOME/.zshrc"
    fi
    
    # Add Go to PATH
    if ! grep -q "/usr/local/go/bin" "$SHELL_RC"; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$SHELL_RC"
    fi
    
    if ! grep -q '$HOME/go/bin' "$SHELL_RC"; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> "$SHELL_RC"
    fi
    
    # Add repo exe/ to PATH (bundled Windows PE tools)
    if ! grep -q "$repo_root/exe" "$SHELL_RC"; then
        echo "export PATH=\$PATH:$repo_root/exe" >> "$SHELL_RC"
    fi
    
    # Add tools directory to PATH
    if ! grep -q '$HOME/tools' "$SHELL_RC"; then
        echo 'export PATH=$PATH:$HOME/tools' >> "$SHELL_RC"
    fi
    
    # Add local bin to PATH
    if ! grep -q '$HOME/.local/bin' "$SHELL_RC"; then
        echo 'export PATH=$PATH:$HOME/.local/bin' >> "$SHELL_RC"
    fi
    
    success "PATH updated in $SHELL_RC"
}

# Verify installations
verify_installations() {
    info "Verifying installations..."
    echo ""
    
    local all_good=true
    
    # Core tools
    if command -v go &> /dev/null; then
        success "Go: $(go version | awk '{print $3}')"
    else
        error "Go: NOT FOUND"
        all_good=false
    fi
    
    if command -v netexec &> /dev/null || command -v nxc &> /dev/null; then
        success "NetExec: $(netexec --version 2>&1 | head -n1 || echo 'installed')"
    else
        error "NetExec: NOT FOUND"
        all_good=false
    fi
    
    if command -v adpack &> /dev/null; then
        success "adpack: installed"
    else
        error "adpack: NOT FOUND"
        all_good=false
    fi
    
    # Optional tools
    if command -v donut &> /dev/null; then
        success "Donut: installed"
    else
        warn "Donut: NOT FOUND (optional)"
    fi
    
    if command -v go-mimikatz &> /dev/null; then
        success "go-mimikatz: installed"
    else
        warn "go-mimikatz: NOT FOUND (optional)"
    fi
    
    if command -v pypykatz &> /dev/null; then
        success "pypykatz: installed"
    else
        warn "pypykatz: NOT FOUND (optional)"
    fi
    
    if command -v ScareCrow &> /dev/null; then
        success "ScareCrow: installed"
    else
        warn "ScareCrow: NOT FOUND (optional)"
    fi
    
    # Windows binaries in exe/
    local repo_root
    repo_root="$(cd "$(dirname "$0")" && pwd)"
    local exe_dir="$repo_root/exe"
    
    if [[ -f "$exe_dir/nanodump.exe" ]]; then
        success "nanodump: $exe_dir/nanodump.exe"
    else
        warn "nanodump: NOT FOUND in exe/ (optional)"
    fi
    
    if [[ -f "$exe_dir/go-mimikatz.exe" ]]; then
        success "go-mimikatz: $exe_dir/go-mimikatz.exe"
    else
        warn "go-mimikatz: NOT FOUND in exe/ (optional)"
    fi
    
    if [[ -f "$exe_dir/MiniPlasma.exe" ]]; then
        success "MiniPlasma: $exe_dir/MiniPlasma.exe"
    else
        warn "MiniPlasma: NOT FOUND in exe/ (optional)"
    fi
    
    if [[ -f "$exe_dir/SweetPotato.exe" ]]; then
        success "SweetPotato: $exe_dir/SweetPotato.exe"
    else
        warn "SweetPotato: NOT FOUND in exe/ (optional)"
    fi
    
    if [[ -f "$exe_dir/PrintSpoofer64.exe" ]]; then
        success "PrintSpoofer64: $exe_dir/PrintSpoofer64.exe"
    else
        warn "PrintSpoofer64: NOT FOUND in exe/ (optional)"
    fi
    
    if [[ -f "$exe_dir/UnDefend.exe" ]]; then
        success "UnDefend: $exe_dir/UnDefend.exe"
    else
        warn "UnDefend: NOT FOUND in exe/ (place your private build here)"
    fi
    
    if [[ -f "$exe_dir/NtApiDotNet.dll" ]] && [[ -f "$exe_dir/Microsoft.Win32.TaskScheduler.dll" ]]; then
        success "MiniPlasma DLLs: present in exe/"
    else
        warn "MiniPlasma DLLs: NOT FOUND in exe/ (needed for MiniPlasma EoP)"
    fi
    
    echo ""
    
    if $all_good; then
        success "All core tools installed successfully!"
    else
        error "Some core tools are missing. Check the log at $LOG_FILE"
        return 1
    fi
}

# Test adpack
test_adpack() {
    info "Testing adpack..."
    
    if adpack status &>> "$LOG_FILE"; then
        success "adpack is working correctly"
    else
        error "adpack test failed. Check the log at $LOG_FILE"
        return 1
    fi
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Setup Complete!                              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo -e "  1. Reload your shell: ${YELLOW}source ~/.bashrc${NC}"
    echo -e "  2. Verify installation: ${YELLOW}adpack status${NC}"
    echo -e "  3. Review configuration: ${YELLOW}cat ~/.adpack/config.yaml${NC}"
    echo ""
    echo -e "${BLUE}Security Notes:${NC}"
    echo -e "  • Credentials are encrypted at rest using AES-GCM in SQLite"
    echo -e "  • Encryption key stored with 600 permissions alongside database"
    echo -e "  • Database permissions set to 600 (owner only)"
    echo -e "  • Use disk encryption and protect the key file for sensitive engagements"
    echo ""
    echo -e "${BLUE}Windows Binaries:${NC}"
    echo -e "  • Bundled in ${YELLOW}exe/${NC} directory (checked into repo)"
    echo -e "  • UnDefend.exe is PRIVATE — place your build in ${YELLOW}exe/UnDefend.exe${NC}"
    echo -e "  • Build missing tools manually or copy pre-built exes to ${YELLOW}exe/${NC}"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo -e "  • README.md - Quick start guide"
    echo -e "  • USAGE.md - Complete command reference"
    echo -e "  • SETUP.md - Detailed setup instructions"
    echo ""
    echo -e "${BLUE}Log file:${NC} $LOG_FILE"
    echo ""
}

# Main installation flow
main() {
    echo "" > "$LOG_FILE"
    log "adpack setup started"
    
    check_os
    check_root
    create_dirs
    install_system_deps
    install_go
    install_pipx
    install_netexec
    install_donut
    install_nanodump
    install_gomimikatz
    install_pypykatz
    install_scarecrow
    install_miniplasma
    build_adpack
    create_config
    update_path
    
    echo ""
    verify_installations
    test_adpack
    print_summary
    
    log "adpack setup completed"
}

# Run main
main
