#!/usr/bin/env bash
#
# BugHunter Pro - Linux / macOS Installer
#
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          BugHunter Pro - Installer v1.0                  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info()    { echo -e "${GREEN}[+]${NC} \$1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} \$1"; }
log_error()   { echo -e "${RED}[-]${NC} \$1"; }
log_step()    { echo -e "${BLUE}[*]${NC} \$1"; }

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_NAME="$ID"
            OS_FAMILY="linux"
        elif [ -f /etc/debian_version ]; then
            OS_NAME="debian"
            OS_FAMILY="linux"
        else
            OS_NAME="linux"
            OS_FAMILY="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_NAME="macos"
        OS_FAMILY="macos"
    else
        OS_NAME="unknown"
        OS_FAMILY="unknown"
    fi
    log_info "Detected OS: $OS_NAME ($OS_FAMILY)"
}

check_python() {
    log_step "Checking Python installation..."

    if command -v python3 &>/dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &>/dev/null; then
        PYTHON_CMD="python"
    else
        log_error "Python 3 not found. Please install Python 3.9+"
        exit 1
    fi

    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.minor)')

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
        log_error "Python 3.9+ required. Found: $PYTHON_VERSION"
        exit 1
    fi

    log_info "Python $PYTHON_VERSION found ($PYTHON_CMD)"
}

install_system_deps() {
    log_step "Installing system dependencies..."

    case "$OS_NAME" in
        kali|parrot|debian|ubuntu|linuxmint|pop)
            log_info "Using apt package manager"
            sudo apt-get update -qq
            sudo apt-get install -y -qq git tor python3-pip python3-venv \
                 python3-dev libffi-dev libssl-dev 2>/dev/null || true
            ;;
        fedora|centos|rhel|rocky|alma)
            log_info "Using dnf/yum package manager"
            sudo dnf install -y git tor python3-pip python3-devel \
                 libffi-devel openssl-devel 2>/dev/null || \
            sudo yum install -y git tor python3-pip python3-devel \
                 libffi-devel openssl-devel 2>/dev/null || true
            ;;
        arch|manjaro|endeavouros|garuda)
            log_info "Using pacman package manager"
            sudo pacman -Sy --noconfirm --needed git tor python-pip \
                 python-setuptools 2>/dev/null || true
            ;;
        opensuse*|sles)
            log_info "Using zypper package manager"
            sudo zypper install -y git tor python3-pip python3-devel 2>/dev/null || true
            ;;
        alpine)
            log_info "Using apk package manager"
            sudo apk add git tor python3 py3-pip 2>/dev/null || true
            ;;
        macos)
            log_info "Using Homebrew"
            if ! command -v brew &>/dev/null; then
                log_warn "Homebrew not found. Installing..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install git tor python@3 2>/dev/null || true
            ;;
        *)
            log_warn "Unknown OS '$OS_NAME'. Skipping system deps."
            log_warn "Please manually install: git, tor, python3-pip"
            ;;
    esac
}

setup_tor() {
    log_step "Configuring Tor service..."

    if [[ "$OS_FAMILY" == "macos" ]]; then
        if command -v tor &>/dev/null; then
            # macOS: Tor runs as a brew service
            brew services start tor 2>/dev/null || true
            log_info "Tor service started via Homebrew"
        else
            log_warn "Tor not installed. Install with: brew install tor"
        fi
    elif [[ "$OS_FAMILY" == "linux" ]]; then
        if command -v tor &>/dev/null; then
            # Enable and start tor service
            if command -v systemctl &>/dev/null; then
                sudo systemctl enable tor 2>/dev/null || true
                sudo systemctl start tor 2>/dev/null || true
                log_info "Tor service enabled and started (systemd)"
            elif command -v service &>/dev/null; then
                sudo service tor start 2>/dev/null || true
                log_info "Tor service started (init.d)"
            else
                log_warn "Cannot auto-start Tor. Start manually: tor &"
            fi
        else
            log_warn "Tor not found after install. Install manually."
        fi
    fi
}

create_venv() {
    log_step "Creating Python virtual environment..."

    VENV_DIR="$HOME/.bughunter_pro_venv"

    if [ -d "$VENV_DIR" ]; then
        log_info "Virtual environment already exists at $VENV_DIR"
    else
        $PYTHON_CMD -m venv "$VENV_DIR"
        log_info "Virtual environment created at $VENV_DIR"
    fi

    # Activate
    source "$VENV_DIR/bin/activate"
    log_info "Virtual environment activated"

    # Upgrade pip
    pip install --upgrade pip setuptools wheel -q
}

install_package() {
    log_step "Installing BugHunter Pro..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    pip install -e ".[dev]" 2>&1 | tail -5
    log_info "BugHunter Pro installed successfully"
}

download_seclists() {
    log_step "Downloading SecLists wordlists..."
    bughunter-install 2>&1 || {
        log_warn "Automatic SecLists download failed."
        log_warn "Run 'bughunter-install' manually after fixing any issues."
    }
}

create_shell_alias() {
    log_step "Creating shell aliases..."

    VENV_DIR="$HOME/.bughunter_pro_venv"
    ALIAS_LINE="alias bughunter='source $VENV_DIR/bin/activate && bughunter'"
    PATH_LINE="export PATH=\"$VENV_DIR/bin:\$PATH\""

    # Detect shell config file
    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
        SHELL_RC="$HOME/.bash_profile"
    else
        SHELL_RC="$HOME/.profile"
    fi

    # Add to shell config if not already present
    if ! grep -q "bughunter_pro_venv" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# BugHunter Pro" >> "$SHELL_RC"
        echo "$PATH_LINE" >> "$SHELL_RC"
        log_info "Added to $SHELL_RC"
    else
        log_info "Already configured in $SHELL_RC"
    fi
}

verify_installation() {
    log_step "Verifying installation..."

    if command -v bughunter &>/dev/null; then
        log_info "bughunter command is available"
    else
        log_warn "bughunter command not in PATH yet."
        log_warn "Either restart your shell or run: source ~/.bashrc"
    fi

    if command -v tor &>/dev/null; then
        log_info "Tor is installed"
    else
        log_warn "⚠️  Tor not found. Anonymous scanning won't work."
    fi

    # Check if SecLists exists
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -d "$SCRIPT_DIR/wordlists/SecLists" ]; then
        log_info "SecLists downloaded"
    else
        log_warn "⚠️  SecLists not found. Run 'bughunter-install'"
    fi
}

main() {
    banner
    detect_os
    check_python
    install_system_deps
    setup_tor
    create_venv
    install_package
    download_seclists
    create_shell_alias
    verify_installation

    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Usage:   ${CYAN}bughunter -d example.com --tor${NC}"
    echo -e "  Help:    ${CYAN}bughunter --help${NC}"
    echo -e "  SecList: ${CYAN}bughunter-install${NC} (re-download if needed)"
    echo ""
    echo -e "  ${YELLOW}⚠️  Restart your terminal or run:${NC}"
    echo -e "     ${CYAN}source ~/.bashrc${NC}  (or ~/.zshrc)"
    echo ""
}

main "$@"