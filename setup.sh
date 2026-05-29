#!/usr/bin/env bash
# adpack setup script — installs all dependencies and builds the tool
# Usage: bash setup.sh

# Save original working directory (critical — install_go cds to /tmp)
ORIG_CWD="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# Directories
TOOLS_DIR="$HOME/tools"; ADPACK_DIR="$HOME/.adpack"; INSTALL_DIR="/usr/local/bin"
LOG_FILE="$HOME/adpack_setup.log"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  adpack Setup Script                      ║${NC}"
echo -e "${BLUE}║          Automated installation of all dependencies       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; log "SUCCESS: $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; log "INFO: $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; log "WARNING: $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; log "ERROR: $1"; }

# Cleanup trap
cleanup() {
    log "Cleanup: returning to $ORIG_CWD"
    cd "$ORIG_CWD" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Retry wrapper — 3 attempts with delay
retry() {
    local desc="$1"; shift
    local max=3; local delay=5
    for i in $(seq 1 $max); do
        if "$@" &>> "$LOG_FILE"; then return 0; fi
        warn "Attempt $i/$max failed: $desc — retrying in ${delay}s..."
        sleep "$delay"
    done
    error "$desc failed after $max attempts"
    return 1
}

check_os() {
    info "Checking operating system..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then success "Running on Linux"; return 0
    elif grep -qi microsoft /proc/version 2>/dev/null; then success "Running on WSL"; return 0
    else error "This script requires Linux or WSL"; exit 1; fi
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. This is not recommended."
        echo -n "Continue anyway? (y/N): "; read -r REPLY
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi
    fi
}

create_dirs() {
    info "Creating directories..."
    mkdir -p "$TOOLS_DIR" "$ADPACK_DIR" "$HOME/.local/bin"
    chmod 700 "$ADPACK_DIR"
    success "Directories created"
}

install_system_deps() {
    info "Installing system dependencies..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y git curl wget build-essential gcc make mingw-w64 \
            python3 python3-pip python3-venv libssl-dev libffi-dev unzip tar gzip \
            mono-complete ldap-utils &>> "$LOG_FILE" || { error "apt-get install failed"; exit 1; }
        success "System dependencies installed (apt)"
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y git curl wget gcc make mingw64-gcc python3 python3-pip \
            openssl-devel libffi-devel unzip tar gzip mono-core openldap-clients &>> "$LOG_FILE" || { error "dnf install failed"; exit 1; }
        success "System dependencies installed (dnf)"
    elif command -v yum &> /dev/null; then
        sudo yum install -y git curl wget gcc make mingw64-gcc python3 python3-pip \
            openssl-devel libffi-devel unzip tar gzip mono-core openldap-clients &>> "$LOG_FILE" || { error "yum install failed"; exit 1; }
        success "System dependencies installed (yum)"
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm git curl wget gcc make mingw-w64-gcc python python-pip \
            openssl libffi unzip tar gzip mono openldap &>> "$LOG_FILE" || { error "pacman install failed"; exit 1; }
        success "System dependencies installed (pacman)"
    else
        warn "Unknown package manager. Please install dependencies manually."
    fi
}

install_go() {
    info "Checking Go installation..."
    GO_INSTALL_VERSION="${GO_VERSION:-1.25.10}"
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        if printf '%s\n' "1.25" "$GO_VERSION" | sort -V -C 2>/dev/null; then
            success "Go $GO_VERSION already installed"; return 0
        fi
        warn "Go version $GO_VERSION is too old. Installing Go $GO_INSTALL_VERSION..."
    fi
    info "Installing Go $GO_INSTALL_VERSION..."
    cd /tmp
    GO_TARBALL="go${GO_INSTALL_VERSION}.linux-amd64.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TARBALL}"
    if ! wget -q --spider "$GO_URL" 2>/dev/null; then
        warn "Go $GO_INSTALL_VERSION not available at $GO_URL — trying 1.24.6"
        GO_INSTALL_VERSION="1.24.6"
        GO_TARBALL="go${GO_INSTALL_VERSION}.linux-amd64.tar.gz"
        GO_URL="https://go.dev/dl/${GO_TARBALL}"
    fi
    retry "Download Go" wget -q "$GO_URL" || exit 1
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    rm -f "$GO_TARBALL"
    if ! grep -q "/usr/local/go/bin" "$HOME/.bashrc"; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
        echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
    fi
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    success "Go $GO_INSTALL_VERSION installed"
}

install_pipx() {
    info "Checking pipx installation..."
    if command -v pipx &> /dev/null; then success "pipx already installed"; return 0; fi
    info "Installing pipx..."
    python3 -m pip install --user pipx &>> "$LOG_FILE" || { error "pipx install failed"; exit 1; }
    python3 -m pipx ensurepath &>> "$LOG_FILE"
    export PATH=$PATH:$HOME/.local/bin
    success "pipx installed"
}

pipx_install_verify() {
    local pkg="$1"; local bin="${2:-$1}"
    if command -v "$bin" &> /dev/null; then success "$pkg already installed"; return 0; fi
    info "Installing $pkg..."
    retry "pipx install $pkg" pipx install "$pkg" || { warn "pipx install $pkg failed"; return 1; }
    if command -v "$bin" &> /dev/null; then
        success "$pkg installed"
        "$bin" --version &>> "$LOG_FILE" 2>&1 || warn "$bin --version failed (may still work)"
    else
        warn "$bin not found after pipx install — check PATH"
    fi
}

install_netexec() { pipx_install_verify "netexec" "netexec"; }
install_pypykatz() { pipx_install_verify "pypykatz" "pypykatz"; }

install_donut() { return 0; }
install_gomimikatz() { return 0; }
install_scarecrow() { return 0; }

install_nanodump() {
    local exe_dir="$ORIG_CWD/exe"; mkdir -p "$exe_dir"
    if [[ -f "$exe_dir/nanodump.exe" ]]; then success "nanodump already in exe/"; return 0; fi
    info "Building nanodump..."
    cd /tmp
    retry "Clone nanodump" git clone https://github.com/fortra/nanodump.git || { warn "nanodump clone failed"; return 1; }
    cd nanodump
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        x86_64-w64-mingw32-gcc -o nanodump.exe source/nanodump.c -ldbghelp -s &>> "$LOG_FILE" && \
            cp nanodump.exe "$exe_dir/" && success "nanodump built"
    else warn "MinGW not available — skipping nanodump build"; fi
    cd /tmp && rm -rf nanodump
}

install_miniplasma() {
    local exe_dir="$ORIG_CWD/exe"; mkdir -p "$exe_dir"
    if [[ -f "$exe_dir/MiniPlasma.exe" ]]; then success "MiniPlasma already in exe/"; return 0; fi
    info "Downloading MiniPlasma..."
    cd /tmp
    if wget -q --spider "https://github.com/Nightmare-Eclipse/MiniPlasma/releases/download/main-release/PoC_AbortHydration_ArbitraryRegKey_EoP.exe" 2>/dev/null; then
        wget -q "https://github.com/Nightmare-Eclipse/MiniPlasma/releases/download/main-release/PoC_AbortHydration_ArbitraryRegKey_EoP.exe" -O MiniPlasma.exe &>> "$LOG_FILE"
        if [[ -f "MiniPlasma.exe" ]] && [[ -s "MiniPlasma.exe" ]]; then
            cp MiniPlasma.exe "$exe_dir/" && success "MiniPlasma installed ($(ls -lh "$exe_dir/MiniPlasma.exe" | awk '{print $5}'))"
        else
            warn "MiniPlasma download failed"
        fi
    else
        warn "MiniPlasma GitHub repo unavailable."
        warn "Build manually from source: https://github.com/Nightmare-Eclipse/MiniPlasma"
        warn "Place MiniPlasma.exe in: $exe_dir/"
    fi
    rm -f /tmp/MiniPlasma.exe
}

install_printspoofer() {
    local exe_dir="$ORIG_CWD/exe"; mkdir -p "$exe_dir"
    if [[ -f "$exe_dir/PrintSpoofer64.exe" ]]; then success "PrintSpoofer64 already in exe/"; return 0; fi
    info "Downloading PrintSpoofer64..."
    cd /tmp
    wget -q "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe" -O PrintSpoofer64.exe &>> "$LOG_FILE"
    if [[ -f "PrintSpoofer64.exe" ]] && [[ -s "PrintSpoofer64.exe" ]]; then
        cp PrintSpoofer64.exe "$exe_dir/" && success "PrintSpoofer64 installed"
    else warn "PrintSpoofer64 download failed"; fi
    rm -f /tmp/PrintSpoofer64.exe
}

install_pplshade() {
    local exe_dir="$ORIG_CWD/exe"; mkdir -p "$exe_dir"
    if [[ -f "$exe_dir/PPLShade.exe" ]]; then success "PPLShade already in exe/"; return 0; fi
    info "Downloading PPLShade (BYOVD PPL bypass)..."
    cd /tmp
    wget -q "https://github.com/redteamfortress/PPLShade/releases/download/v1.0.0/Release.zip" -O PPLShade.zip &>> "$LOG_FILE"
    if [[ -f "PPLShade.zip" ]] && [[ -s "PPLShade.zip" ]]; then
        unzip -o PPLShade.zip &>> "$LOG_FILE"
        cp PPLShade.exe "$exe_dir/" 2>/dev/null || warn "PPLShade.exe not in zip (check structure)"
        cp LECOMAx64.sys "$exe_dir/" 2>/dev/null || warn "LECOMAx64.sys not in zip"
        success "PPLShade installed"
    else
        warn "PPLShade download failed — build manually from https://github.com/redteamfortress/PPLShade"
    fi
    rm -rf /tmp/PPLShade.zip /tmp/PPLShade /tmp/Release 2>/dev/null
}

install_phantomkiller() {
    local exe_dir="$ORIG_CWD/exe"; mkdir -p "$exe_dir"
    if [[ -f "$exe_dir/PhantomKiller.exe" ]]; then success "PhantomKiller already in exe/"; return 0; fi
    info "Downloading PhantomKiller (BYOVD process killer)..."
    cd /tmp
    wget -q "https://github.com/redteamfortress/PhantomKiller/releases/download/v1.0.0/PhantomKiller.zip" -O PhantomKiller.zip &>> "$LOG_FILE"
    if [[ -f "PhantomKiller.zip" ]] && [[ -s "PhantomKiller.zip" ]]; then
        unzip -o PhantomKiller.zip &>> "$LOG_FILE"
        cp PhantomKiller.exe "$exe_dir/" 2>/dev/null || warn "PhantomKiller.exe not in zip"
        cp PhantomKiller.sys "$exe_dir/" 2>/dev/null || warn "PhantomKiller.sys not in zip"
        success "PhantomKiller installed"
    else
        warn "PhantomKiller download failed — build manually from https://github.com/redteamfortress/PhantomKiller"
    fi
    rm -rf /tmp/PhantomKiller.zip /tmp/PhantomKiller 2>/dev/null
}

build_adpack() {
    cd "$ORIG_CWD" || { error "Cannot cd to $ORIG_CWD"; exit 1; }
    info "Building adpack..."
    if [[ ! -f "go.mod" ]]; then error "go.mod not found in $ORIG_CWD"; exit 1; fi
    go mod download &>> "$LOG_FILE" || { error "go mod download failed"; exit 1; }
    go build -o adpack . &>> "$LOG_FILE" || { error "go build failed"; exit 1; }
    if [[ -f "adpack" ]]; then
        sudo cp adpack /usr/local/bin/ && success "adpack built and installed to /usr/local/bin/adpack"
    else error "adpack binary not found after build"; exit 1; fi
}

create_config() {
    info "Creating configuration..."
    if [[ -f "$ADPACK_DIR/config.yaml" ]]; then warn "Config already exists at $ADPACK_DIR/config.yaml"; return 0; fi
    cat > "$ADPACK_DIR/config.yaml" << EOF
# adpack configuration
db_path: "$HOME/.adpack/state.db"
domain: ""
profile: "undefend"

# Tool paths
nxc_path: "netexec"
bh_python: "bloodhound-python"

# Cracking
cracking:
  hashcat_path: "hashcat"
  wordlist: "/usr/share/wordlists/rockyou.txt"
  rules: []
  timeout: 300

# Scope (optional — restrict to these CIDR ranges)
# scope:
#   - "10.0.0.0/8"

# Timing controls
timing:
  delay_ms: 0
  jitter: 0.0
  max_concurrent: 10
EOF
    success "Configuration created at $ADPACK_DIR/config.yaml"
}

update_path() {
    info "Updating PATH..."
    SHELL_RC="$HOME/.bashrc"
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
    for entry in "/usr/local/go/bin" "$HOME/go/bin" "$HOME/.local/bin" "$HOME/tools" "$ORIG_CWD/exe"; do
        if ! grep -qF "$entry" "$SHELL_RC" 2>/dev/null; then
            echo "export PATH=\$PATH:$entry" >> "$SHELL_RC"
        fi
    done
    success "PATH updated in $SHELL_RC"
}

verify_installations() {
    info "Verifying installations..."; echo ""
    local all_good=true
    check_cmd() { if command -v "$1" &> /dev/null; then success "$1: $(command -v "$1")"; else error "$1: NOT FOUND"; all_good=false; fi; }
    check_file() { if [[ -f "$1" ]]; then success "$(basename "$1"): $1"; else warn "$(basename "$1"): NOT FOUND (optional)"; fi; }
    check_cmd "go"; check_cmd "netexec"; check_cmd "adpack"; check_cmd "pypykatz"
    local exe_dir="$ORIG_CWD/exe"
    check_file "$exe_dir/nanodump.exe"
    check_file "$exe_dir/MiniPlasma.exe"; check_file "$exe_dir/PrintSpoofer64.exe"
    check_file "$exe_dir/PPLShade.exe"; check_file "$exe_dir/LECOMAx64.sys"
    check_file "$exe_dir/PhantomKiller.exe"; check_file "$exe_dir/PhantomKiller.sys"
    echo ""
    if $all_good; then success "All core tools installed!"; else error "Some core tools missing — check $LOG_FILE"; return 1; fi
}

test_adpack() {
    info "Testing adpack..."
    if adpack status &>> "$LOG_FILE"; then success "adpack is working"
    else error "adpack test failed — check $LOG_FILE"; return 1; fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Setup Complete!                              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo -e "  1. Reload shell: ${YELLOW}source ~/.bashrc${NC}"
    echo -e "  2. Verify: ${YELLOW}adpack status${NC}"
    echo -e "  3. Config: ${YELLOW}cat ~/.adpack/config.yaml${NC}"
    echo ""
    echo -e "${BLUE}Evasion profiles (select with -e flag):${NC}"
    echo -e "    ${YELLOW}undefend${NC}       — Native AV kill (reg add + sc stop + taskkill)"
    echo -e "    ${YELLOW}pplshade${NC}       — PPL bypass via BYOVD (PPLShade + LECOMAx64.sys)"
    echo -e "    ${YELLOW}phantomkiller${NC}  — EDR kill via BYOVD (PhantomKiller + PhantomKiller.sys)"
    echo ""
    echo -e "${BLUE}Log:${NC} $LOG_FILE"
    echo ""
}

main() {
    echo "" > "$LOG_FILE"
    log "adpack setup started"
    check_os; check_root; create_dirs; install_system_deps
    install_go; install_pipx
    install_netexec; install_nanodump; install_pypykatz
    install_miniplasma; install_printspoofer; install_pplshade; install_phantomkiller
    build_adpack; create_config; update_path
    echo ""; verify_installations; test_adpack; print_summary
    log "adpack setup completed"
}

main
