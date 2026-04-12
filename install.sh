#!/usr/bin/env bash
#
# BugHunter Pro - Linux / macOS Installer (FIXED)
# University of Hertfordshire - Cyber Security
#
set -e

# ============================================================
# CONFIGURATION
# ============================================================
VENV_DIR="$HOME/.bughunter_pro_venv"
WRAPPER_DIR="$HOME/.local/bin"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================
# LOGGING
# ============================================================
log_info()    { echo -e "${GREEN}[+]${NC} \$1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} \$1"; }
log_error()   { echo -e "${RED}[-]${NC} \$1"; }
log_step()    { echo -e "${BLUE}[*]${NC} \$1"; }

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          BugHunter Pro - Installer v1.0                  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ============================================================
# OS DETECTION
# ============================================================
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_NAME="$ID"
        elif [ -f /etc/debian_version ]; then
            OS_NAME="debian"
        else
            OS_NAME="linux"
        fi
        OS_FAMILY="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_NAME="macos"
        OS_FAMILY="macos"
    else
        OS_NAME="unknown"
        OS_FAMILY="unknown"
    fi
    log_info "Detected OS: ${BOLD}$OS_NAME${NC} ($OS_FAMILY)"
}

# ============================================================
# PYTHON CHECK
# ============================================================
check_python() {
    log_step "Checking Python installation..."

    PYTHON_CMD=""
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            PY_MAJOR=$($cmd -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
            PY_MINOR=$($cmd -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")
            if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 9 ]; then
                PYTHON_CMD="$cmd"
                break
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        log_error "Python 3.9+ not found!"
        log_error "Install Python: https://www.python.org/downloads/"
        exit 1
    fi

    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1)
    log_info "Found: ${BOLD}$PYTHON_VERSION${NC} ($PYTHON_CMD)"
}

# ============================================================
# SYSTEM DEPENDENCIES
# ============================================================
install_system_deps() {
    log_step "Installing system dependencies..."

    case "$OS_NAME" in
        kali|parrot|debian|ubuntu|linuxmint|pop|elementary|zorin)
            log_info "Using apt package manager..."
            sudo apt-get update -qq 2>/dev/null || true
            sudo apt-get install -y -qq \
                git tor curl python3-pip python3-venv \
                python3-dev libffi-dev libssl-dev 2>/dev/null || true
            ;;
        fedora)
            log_info "Using dnf package manager..."
            sudo dnf install -y git tor python3-pip python3-devel \
                libffi-devel openssl-devel 2>/dev/null || true
            ;;
        centos|rhel|rocky|alma)
            log_info "Using yum/dnf package manager..."
            sudo dnf install -y git tor python3-pip python3-devel 2>/dev/null || \
            sudo yum install -y git tor python3-pip python3-devel 2>/dev/null || true
            ;;
        arch|manjaro|endeavouros|garuda)
            log_info "Using pacman package manager..."
            sudo pacman -Sy --noconfirm --needed \
                git tor python python-pip python-setuptools 2>/dev/null || true
            ;;
        opensuse*|sles)
            log_info "Using zypper package manager..."
            sudo zypper install -y git tor python3-pip python3-devel 2>/dev/null || true
            ;;
        alpine)
            log_info "Using apk package manager..."
            sudo apk add git tor python3 py3-pip 2>/dev/null || true
            ;;
        void)
            log_info "Using xbps package manager..."
            sudo xbps-install -y git tor python3-pip 2>/dev/null || true
            ;;
        macos)
            log_info "Using Homebrew..."
            if ! command -v brew &>/dev/null; then
                log_warn "Homebrew not found. Installing..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || true
            fi
            brew install git tor python@3 2>/dev/null || true
            ;;
        *)
            log_warn "Unknown OS '$OS_NAME'. Skipping system packages."
            log_warn "Manually install: git, tor, python3, python3-pip, python3-venv"
            ;;
    esac

    log_info "System dependencies installed"
}

# ============================================================
# TOR SETUP
# ============================================================
setup_tor() {
    log_step "Configuring Tor service..."

    if ! command -v tor &>/dev/null; then
        log_warn "Tor binary not found. Tor features will be unavailable."
        log_warn "Install manually and re-run, or use --tor flag when scanning."
        return
    fi

    if [[ "$OS_FAMILY" == "macos" ]]; then
        brew services start tor 2>/dev/null || true
        log_info "Tor service started (Homebrew)"
    elif [[ "$OS_FAMILY" == "linux" ]]; then
        if command -v systemctl &>/dev/null; then
            sudo systemctl enable tor 2>/dev/null || true
            sudo systemctl start tor 2>/dev/null || true
            log_info "Tor service enabled and started (systemd)"
        elif command -v service &>/dev/null; then
            sudo service tor start 2>/dev/null || true
            log_info "Tor service started (init.d)"
        else
            log_warn "Could not auto-start Tor. Start manually: tor &"
        fi
    fi
}

# ============================================================
# VIRTUAL ENVIRONMENT
# ============================================================
create_venv() {
    log_step "Creating Python virtual environment at ${BOLD}$VENV_DIR${NC}..."

    if [ -d "$VENV_DIR" ]; then
        log_info "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    fi

    $PYTHON_CMD -m venv "$VENV_DIR"

    if [ ! -f "$VENV_DIR/bin/activate" ]; then
        log_error "Failed to create virtual environment!"
        log_error "Try: $PYTHON_CMD -m ensurepip --upgrade"
        log_error "Then: $PYTHON_CMD -m pip install virtualenv"
        exit 1
    fi

    log_info "Virtual environment created"

    # Activate it within this script
    source "$VENV_DIR/bin/activate"

    # Upgrade pip inside venv
    pip install --upgrade pip setuptools wheel -q 2>/dev/null
    log_info "pip/setuptools/wheel upgraded"
}

# ============================================================
# INSTALL PACKAGE
# ============================================================
install_package() {
    log_step "Installing BugHunter Pro package..."

    cd "$PROJECT_DIR"

    # Install the package in editable mode
    pip install -e . 2>&1 | tail -3

    # Verify the entry points were created inside the venv
    if [ -f "$VENV_DIR/bin/bughunter" ]; then
        log_info "bughunter entry point created in venv"
    else
        log_warn "Entry point not found. Trying pip install again..."
        pip install -e . --force-reinstall --no-deps 2>&1 | tail -3
    fi

    log_info "BugHunter Pro package installed"
}

# ============================================================
# CREATE WRAPPER SCRIPTS (THE KEY FIX)
# ============================================================
create_wrapper_scripts() {
    log_step "Creating command-line wrapper scripts..."

    # Create wrapper directory
    mkdir -p "$WRAPPER_DIR"

    # ---- bughunter wrapper ----
    cat > "$WRAPPER_DIR/bughunter" << WRAPPER_EOF
#!/usr/bin/env bash
# BugHunter Pro - Auto-generated wrapper script
# This activates the virtual environment and runs the tool

VENV_DIR="$VENV_DIR"

if [ ! -f "\$VENV_DIR/bin/activate" ]; then
    echo "ERROR: BugHunter Pro virtual environment not found at \$VENV_DIR"
    echo "Please reinstall: cd $PROJECT_DIR && ./install.sh"
    exit 1
fi

# Activate venv and run
source "\$VENV_DIR/bin/activate"
exec python -m bughunter_pro "\$@"
WRAPPER_EOF
    chmod +x "$WRAPPER_DIR/bughunter"
    log_info "Created: $WRAPPER_DIR/bughunter"

    # ---- bughunter-dashboard wrapper ----
    cat > "$WRAPPER_DIR/bughunter-dashboard" << WRAPPER_EOF
#!/usr/bin/env bash
# BugHunter Pro Dashboard - Auto-generated wrapper script

VENV_DIR="$VENV_DIR"

if [ ! -f "\$VENV_DIR/bin/activate" ]; then
    echo "ERROR: BugHunter Pro virtual environment not found at \$VENV_DIR"
    echo "Please reinstall: cd $PROJECT_DIR && ./install.sh"
    exit 1
fi

source "\$VENV_DIR/bin/activate"

echo ""
echo "🛡️  BugHunter Pro Dashboard"
echo "=================================================="
echo "  URL: http://localhost:8501"
echo "  Press Ctrl+C to stop"
echo "=================================================="
echo ""

DASHBOARD_PATH="$PROJECT_DIR/dashboard/app.py"

if [ ! -f "\$DASHBOARD_PATH" ]; then
    echo "ERROR: Dashboard not found at \$DASHBOARD_PATH"
    exit 1
fi

exec python -m streamlit run "\$DASHBOARD_PATH" \\
    --server.headless=true \\
    --server.port=8501 \\
    --browser.gatherUsageStats=false \\
    --theme.base=dark \\
    --theme.primaryColor="#58a6ff" \\
    --theme.backgroundColor="#0d1117" \\
    --theme.secondaryBackgroundColor="#161b22" \\
    --theme.textColor="#c9d1d9" \\
    "\$@"
WRAPPER_EOF
    chmod +x "$WRAPPER_DIR/bughunter-dashboard"
    log_info "Created: $WRAPPER_DIR/bughunter-dashboard"

    # ---- bughunter-install wrapper ----
    cat > "$WRAPPER_DIR/bughunter-install" << WRAPPER_EOF
#!/usr/bin/env bash
# BugHunter Pro SecLists Installer - Auto-generated wrapper script

VENV_DIR="$VENV_DIR"

if [ ! -f "\$VENV_DIR/bin/activate" ]; then
    echo "ERROR: BugHunter Pro virtual environment not found at \$VENV_DIR"
    exit 1
fi

source "\$VENV_DIR/bin/activate"
exec python -c "from bughunter_pro.installer import main; main()" "\$@"
WRAPPER_EOF
    chmod +x "$WRAPPER_DIR/bughunter-install"
    log_info "Created: $WRAPPER_DIR/bughunter-install"

    log_info "All wrapper scripts created in $WRAPPER_DIR"
}

# ============================================================
# ADD TO PATH
# ============================================================
add_to_path() {
    log_step "Adding $WRAPPER_DIR to PATH..."

    PATH_LINE="export PATH=\"$WRAPPER_DIR:\$PATH\""
    COMMENT_LINE="# BugHunter Pro - added by installer"

    # Determine which shell config files to update
    SHELL_CONFIGS=()

    # Always try .profile as a fallback
    [ -f "$HOME/.profile" ] && SHELL_CONFIGS+=("$HOME/.profile")

    # Bash
    [ -f "$HOME/.bashrc" ] && SHELL_CONFIGS+=("$HOME/.bashrc")
    [ -f "$HOME/.bash_profile" ] && SHELL_CONFIGS+=("$HOME/.bash_profile")

    # Zsh
    [ -f "$HOME/.zshrc" ] && SHELL_CONFIGS+=("$HOME/.zshrc")
    [ -f "$HOME/.zshenv" ] && SHELL_CONFIGS+=("$HOME/.zshenv")

    # Fish (different syntax)
    if [ -f "$HOME/.config/fish/config.fish" ]; then
        FISH_CONFIG="$HOME/.config/fish/config.fish"
        if ! grep -q "bughunter" "$FISH_CONFIG" 2>/dev/null; then
            echo "" >> "$FISH_CONFIG"
            echo "# BugHunter Pro - added by installer" >> "$FISH_CONFIG"
            echo "set -gx PATH $WRAPPER_DIR \$PATH" >> "$FISH_CONFIG"
            log_info "Updated: $FISH_CONFIG"
        fi
    fi

    # If no config files found, create .bashrc
    if [ ${#SHELL_CONFIGS[@]} -eq 0 ]; then
        SHELL_CONFIGS+=("$HOME/.bashrc")
        touch "$HOME/.bashrc"
    fi

    # Add PATH to each config file
    UPDATED_FILES=()
    for config_file in "${SHELL_CONFIGS[@]}"; do
        if ! grep -q "bughunter" "$config_file" 2>/dev/null; then
            echo "" >> "$config_file"
            echo "$COMMENT_LINE" >> "$config_file"
            echo "$PATH_LINE" >> "$config_file"
            UPDATED_FILES+=("$config_file")
        fi
    done

    if [ ${#UPDATED_FILES[@]} -gt 0 ]; then
        log_info "PATH added to: ${UPDATED_FILES[*]}"
    else
        log_info "PATH already configured in shell config files"
    fi

    # ALSO: export for current script session
    export PATH="$WRAPPER_DIR:$PATH"
}

# ============================================================
# DOWNLOAD SECLISTS
# ============================================================
download_seclists() {
    log_step "Downloading SecLists wordlists..."

    # Activate venv for this operation
    source "$VENV_DIR/bin/activate"

    python -c "from bughunter_pro.installer import download_seclists; download_seclists()" 2>&1 || {
        log_warn "SecLists download failed (may need manual download)."
        log_warn "Run later: bughunter-install"
        # Create fallback wordlists
        python -c "
from bughunter_pro.installer import generate_fallback_wordlists, WORDLIST_DIR, setup_logging
import pathlib
pathlib.Path(str(WORDLIST_DIR)).mkdir(parents=True, exist_ok=True)
generate_fallback_wordlists(setup_logging())
" 2>/dev/null || true
    }
}

# ============================================================
# VERIFY INSTALLATION
# ============================================================
verify_installation() {
    log_step "Verifying installation..."

    local ALL_OK=true

    # Check wrapper scripts exist
    if [ -x "$WRAPPER_DIR/bughunter" ]; then
        log_info "✅ bughunter wrapper script exists"
    else
        log_error "❌ bughunter wrapper script not found"
        ALL_OK=false
    fi

    if [ -x "$WRAPPER_DIR/bughunter-dashboard" ]; then
        log_info "✅ bughunter-dashboard wrapper script exists"
    else
        log_error "❌ bughunter-dashboard wrapper script not found"
        ALL_OK=false
    fi

    # Check venv exists
    if [ -f "$VENV_DIR/bin/activate" ]; then
        log_info "✅ Virtual environment exists"
    else
        log_error "❌ Virtual environment not found"
        ALL_OK=false
    fi

    # Check package is importable
    source "$VENV_DIR/bin/activate"
    if python -c "import bughunter_pro" 2>/dev/null; then
        log_info "✅ bughunter_pro package importable"
    else
        log_error "❌ bughunter_pro package not importable"
        ALL_OK=false
    fi

    # Check bughunter command works (using wrapper directly)
    if "$WRAPPER_DIR/bughunter" --help &>/dev/null; then
        log_info "✅ bughunter --help works"
    else
        log_warn "⚠️  bughunter --help returned non-zero (may still work)"
    fi

    # Check Tor
    if command -v tor &>/dev/null; then
        log_info "✅ Tor is installed"
    else
        log_warn "⚠️  Tor not found (--tor flag won't work)"
    fi

    # Check SecLists
    if [ -d "$PROJECT_DIR/wordlists/SecLists" ]; then
        log_info "✅ SecLists downloaded"
    elif [ -d "$PROJECT_DIR/wordlists/fallback" ]; then
        log_warn "⚠️  Using fallback wordlists (SecLists not fully downloaded)"
    else
        log_warn "⚠️  No wordlists found. Run: bughunter-install"
    fi

    # Check PATH
    if echo "$PATH" | grep -q "$WRAPPER_DIR"; then
        log_info "✅ $WRAPPER_DIR is in current PATH"
    else
        log_warn "⚠️  $WRAPPER_DIR not in current PATH (restart shell needed)"
    fi

    echo ""
    if $ALL_OK; then
        log_info "All checks passed! ✅"
    else
        log_warn "Some checks failed. See warnings above."
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    banner
    echo ""

    # Pre-flight
    detect_os
    check_python
    echo ""

    # System setup
    install_system_deps
    setup_tor
    echo ""

    # Python setup
    create_venv
    install_package
    echo ""

    # Command-line access (THE KEY FIX)
    create_wrapper_scripts
    add_to_path
    echo ""

    # Wordlists
    download_seclists
    echo ""

    # Verify
    verify_installation
    echo ""

    # ============================================================
    # SUCCESS MESSAGE
    # ============================================================
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                          ║${NC}"
    echo -e "${GREEN}║           ✅ Installation Complete!                      ║${NC}"
    echo -e "${GREEN}║                                                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Quick Start:${NC}"
    echo ""
    echo -e "    ${CYAN}bughunter -d example.com${NC}              # Basic scan"
    echo -e "    ${CYAN}bughunter -d example.com --tor${NC}        # Scan via Tor"
    echo -e "    ${CYAN}bughunter -d example.com --full --tor${NC} # Full scan"
    echo -e "    ${CYAN}bughunter-dashboard${NC}                   # Open dashboard"
    echo -e "    ${CYAN}bughunter --help${NC}                      # Show all options"
    echo ""
    echo -e "  ${BOLD}SecLists Management:${NC}"
    echo ""
    echo -e "    ${CYAN}bughunter-install${NC}                     # Download SecLists"
    echo -e "    ${CYAN}bughunter-install --info${NC}              # Show wordlist info"
    echo ""
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}  IMPORTANT: To use 'bughunter' in this terminal NOW:${NC}"
    echo ""
    echo -e "    ${BOLD}${CYAN}source ~/.bashrc${NC}       ${YELLOW}(for bash users)${NC}"
    echo -e "    ${BOLD}${CYAN}source ~/.zshrc${NC}        ${YELLOW}(for zsh users)${NC}"
    echo ""
    echo -e "  ${YELLOW}  OR simply open a new terminal window.${NC}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Offer to source now
    echo -e -n "  ${BOLD}Would you like to apply PATH changes now? [Y/n]:${NC} "
    read -r APPLY_NOW

    if [[ "$APPLY_NOW" != "n" && "$APPLY_NOW" != "N" ]]; then
        # Detect current shell and source appropriate file
        CURRENT_SHELL=$(basename "$SHELL" 2>/dev/null || echo "bash")

        case "$CURRENT_SHELL" in
            zsh)
                echo ""
                echo -e "  Run this command to activate:"
                echo ""
                echo -e "    ${BOLD}${CYAN}source ~/.zshrc${NC}"
                ;;
            fish)
                echo ""
                echo -e "  Run this command to activate:"
                echo ""
                echo -e "    ${BOLD}${CYAN}source ~/.config/fish/config.fish${NC}"
                ;;
            *)
                echo ""
                echo -e "  Run this command to activate:"
                echo ""
                echo -e "    ${BOLD}${CYAN}source ~/.bashrc${NC}"
                ;;
        esac

        echo ""
        echo -e "  After sourcing, test with: ${CYAN}bughunter --help${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Installation paths:${NC}"
    echo -e "    Venv:     $VENV_DIR"
    echo -e "    Wrappers: $WRAPPER_DIR"
    echo -e "    Project:  $PROJECT_DIR"
    echo ""
}

main "$@"