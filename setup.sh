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
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
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
            unzip tar gzip &>> "$LOG_FILE"
        success "System dependencies installed"
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            git curl wget gcc make \
            mingw64-gcc python3 python3-pip \
            openssl-devel libffi-devel \
            unzip tar gzip &>> "$LOG_FILE"
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
    
    info "Installing Go 1.25.0..."
    cd /tmp
    wget -q https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
    rm go1.25.0.linux-amd64.tar.gz
    
    # Add to PATH if not already there
    if ! grep -q "/usr/local/go/bin" "$HOME/.bashrc"; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
        echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:$HOME/go/bin
    
    success "Go 1.25.0 installed"
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
    info "Checking nanodump installation..."
    
    if [[ -f "$TOOLS_DIR/nanodump.exe" ]]; then
        success "nanodump already installed"
        return 0
    fi
    
    info "Building nanodump..."
    cd /tmp
    git clone https://github.com/fortra/nanodump.git &>> "$LOG_FILE"
    cd nanodump
    
    # Build with MinGW
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s &>> "$LOG_FILE"
        cp nanodump.exe "$TOOLS_DIR/"
        success "nanodump built and installed"
    else
        warn "MinGW not available. Skipping nanodump build."
        warn "You can build it manually on Windows or download a pre-compiled binary."
    fi
    
    cd /tmp
    rm -rf nanodump
}

# Install go-mimikatz
install_gomimikatz() {
    info "Checking go-mimikatz installation..."
    
    if command -v go-mimikatz &> /dev/null; then
        success "go-mimikatz already installed"
        return 0
    fi
    
    info "Building go-mimikatz..."
    cd /tmp
    git clone https://github.com/vyrus001/go-mimikatz.git &>> "$LOG_FILE"
    cd go-mimikatz
    go build -o go-mimikatz main.go &>> "$LOG_FILE"
    sudo cp go-mimikatz /usr/local/bin/
    cd /tmp
    rm -rf go-mimikatz
    
    success "go-mimikatz installed"
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

# Create placeholder evasion tools
create_evasion_placeholders() {
    info "Creating placeholder evasion tools..."
    
    # UnDefend.exe placeholder
    if [[ ! -f "$TOOLS_DIR/UnDefend.exe" ]]; then
        cat > "$TOOLS_DIR/UnDefend.exe" << 'EOF'
#!/bin/bash
echo "[*] UnDefend.exe placeholder - replace with actual binary"
echo "[!] This is a placeholder. Build UnDefend.exe on Windows and copy here."
EOF
        chmod +x "$TOOLS_DIR/UnDefend.exe"
        warn "UnDefend.exe placeholder created at $TOOLS_DIR/UnDefend.exe"
    fi
    
    # FunnyApp.exe (BlueHammer) placeholder
    if [[ ! -f "$TOOLS_DIR/FunnyApp.exe" ]]; then
        cat > "$TOOLS_DIR/FunnyApp.exe" << 'EOF'
#!/bin/bash
echo "[*] FunnyApp.exe (BlueHammer) placeholder - replace with actual exploit"
echo "[!] This is a placeholder for CVE-2026-33825 exploit."
EOF
        chmod +x "$TOOLS_DIR/FunnyApp.exe"
        warn "FunnyApp.exe placeholder created at $TOOLS_DIR/FunnyApp.exe"
    fi
    
    # EDR-Freeze.exe placeholder
    if [[ ! -f "$TOOLS_DIR/EDR-Freeze.exe" ]]; then
        cat > "$TOOLS_DIR/EDR-Freeze.exe" << 'EOF'
#!/bin/bash
echo "[*] EDR-Freeze.exe placeholder - replace with actual binary"
echo "[!] This is a placeholder. Build EDR-Freeze on Windows and copy here."
EOF
        chmod +x "$TOOLS_DIR/EDR-Freeze.exe"
        warn "EDR-Freeze.exe placeholder created at $TOOLS_DIR/EDR-Freeze.exe"
    fi
    
    success "Evasion tool placeholders created"
}

# Build adpack
build_adpack() {
    info "Building adpack..."
    
    if [[ ! -f "go.mod" ]]; then
        error "go.mod not found. Are you in the adpack directory?"
        exit 1
    fi
    
    go mod download &>> "$LOG_FILE"
    go build -o adpack main.go &>> "$LOG_FILE"
    
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

target:
  domain: ""
  dc_ip: ""
  username: ""
  password: ""

tools:
  netexec: "netexec"
  donut: "donut"
  nanodump: "$TOOLS_DIR/nanodump.exe"
  gomimikatz: "go-mimikatz"
  pypykatz: "pypykatz"
  scarecrow: "ScareCrow"
  undefend: "$TOOLS_DIR/UnDefend.exe"
  bluehammer: "$TOOLS_DIR/FunnyApp.exe"
  edrfreeze: "$TOOLS_DIR/EDR-Freeze.exe"
  rtcore: "$TOOLS_DIR/RTCore64.sys"

evasion:
  default_profile: "standard"
  command_timeout: 120
  retry_on_failure: false
  max_retries: 3

output:
  verbose: false
  save_raw_output: true
  raw_output_dir: "./output"
  json_output: false

phases:
  skip_completed: true
  auto_advance: false
EOF
    
    success "Configuration created at $ADPACK_DIR/config.yaml"
}

# Update PATH in shell config
update_path() {
    info "Updating PATH in shell configuration..."
    
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
    
    if [[ -f "$TOOLS_DIR/nanodump.exe" ]]; then
        success "nanodump: $TOOLS_DIR/nanodump.exe"
    else
        warn "nanodump: NOT FOUND (optional)"
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
    echo -e "  3. Check available profiles: ${YELLOW}adpack profiles${NC}"
    echo -e "  4. Review configuration: ${YELLOW}cat ~/.adpack/config.yaml${NC}"
    echo ""
    echo -e "${BLUE}Optional:${NC}"
    echo -e "  • Replace placeholder tools in ${YELLOW}$TOOLS_DIR/${NC}"
    echo -e "  • Build Windows-specific tools (UnDefend, EDR-Freeze, etc.)"
    echo -e "  • Set up a vulnerable AD lab (VulnAD, GOAD)"
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
    create_evasion_placeholders
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
