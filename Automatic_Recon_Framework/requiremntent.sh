#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Automatic Recon Framework - Tool & Dependency Installer
# Author: Ojasva Srivastava
# For Kali/Debian/Ubuntu based systems
# ============================================================

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"

log()  { echo -e "${BLUE}[*]${RESET} $1"; }
ok()   { echo -e "${GREEN}[+]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
err()  { echo -e "${RED}[x]${RESET} $1"; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

install_apt_pkg() {
    local pkg="$1"
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        ok "$pkg already installed"
    else
        log "Installing $pkg"
        sudo apt-get install -y "$pkg"
    fi
}

install_go_tool() {
    local name="$1"
    local module="$2"

    if need_cmd "$name"; then
        ok "$name already installed"
        return
    fi

    log "Installing $name"
    go install "$module"

    if need_cmd "$name"; then
        ok "$name installed"
    elif [ -x "$HOME/go/bin/$name" ]; then
        ok "$name installed in $HOME/go/bin"
    else
        warn "$name may not be in PATH. Check $HOME/go/bin"
    fi
}

ensure_path() {
    if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
        warn "\$HOME/go/bin is not in PATH for this shell."
        echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.bashrc"
        echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.zshrc" 2>/dev/null || true
        export PATH="$PATH:$HOME/go/bin"
        ok "Added $HOME/go/bin to .bashrc/.zshrc"
    fi
}

install_massdns() {
    if need_cmd massdns; then
        ok "massdns already installed"
        return
    fi

    log "Installing massdns from source"
    local tmpdir
    tmpdir="$(mktemp -d)"
    git clone --depth 1 https://github.com/blechschmidt/massdns.git "$tmpdir/massdns"
    make -C "$tmpdir/massdns"
    sudo cp "$tmpdir/massdns/bin/massdns" /usr/local/bin/massdns
    rm -rf "$tmpdir"

    if need_cmd massdns; then
        ok "massdns installed"
    else
        err "massdns installation failed"
    fi
}

install_altdns() {
    if need_cmd altdns; then
        ok "altdns already installed"
        return
    fi

    log "Installing altdns with pipx/pip"
    if need_cmd pipx; then
        pipx install py-altdns || warn "pipx altdns install failed"
    fi

    if ! need_cmd altdns; then
        python3 -m pip install --user py-altdns || warn "pip altdns install failed"
    fi

    if need_cmd altdns; then
        ok "altdns installed"
    else
        warn "altdns not found in PATH after install. It is optional."
    fi
}

install_arjun() {
    if need_cmd arjun; then
        ok "arjun already installed"
        return
    fi

    log "Installing arjun"
    if need_cmd pipx; then
        pipx install arjun || warn "pipx arjun install failed"
    fi

    if ! need_cmd arjun; then
        python3 -m pip install --user arjun || warn "pip arjun install failed"
    fi

    if need_cmd arjun; then
        ok "arjun installed"
    else
        warn "arjun not found in PATH after install. It is optional."
    fi
}

install_waybackurls() {
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
}

install_assetfinder() {
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
}

install_ffuf() {
    install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"
}

install_projectdiscovery_tools() {
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "dnsx"      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"

    # Optional ProjectDiscovery tools
    install_go_tool "naabu"  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" || true
    install_go_tool "asnmap" "github.com/projectdiscovery/asnmap/cmd/asnmap@latest" || true
    install_go_tool "mapcidr" "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest" || true
}

install_python_dependencies() {
    log "Installing Python dependencies"
    python3 -m pip install --user -r requirements.txt
    ok "Python dependencies installed"
}

install_wordlists() {
    log "Checking SecLists"
    if [ -d "/usr/share/seclists" ]; then
        ok "SecLists already installed"
    else
        install_apt_pkg seclists
    fi
}

print_summary() {
    echo
    echo -e "${GREEN}============================================================${RESET}"
    echo -e "${GREEN} Installation Summary${RESET}"
    echo -e "${GREEN}============================================================${RESET}"

    local tools=(
        python3 pip3 git curl jq go
        subfinder assetfinder shuffledns massdns dnsx httpx katana waybackurls nuclei ffuf
        altdns arjun naabu asnmap mapcidr parallel
    )

    for t in "${tools[@]}"; do
        if need_cmd "$t"; then
            echo -e "${GREEN}[OK]${RESET} $t -> $(command -v "$t")"
        else
            echo -e "${YELLOW}[MISSING/OPTIONAL]${RESET} $t"
        fi
    done

    echo
    echo "If Go tools are missing from PATH, run:"
    echo '  export PATH="$PATH:$HOME/go/bin"'
    echo
    echo "Then test:"
    echo "  ./run.sh -h"
}

main() {
    echo -e "${GREEN}"
    echo "============================================================"
    echo " Automatic Recon Framework - Dependency Installer"
    echo "============================================================"
    echo -e "${RESET}"

    if ! need_cmd sudo; then
        err "sudo not found. Run this on Kali/Debian/Ubuntu with sudo available."
        exit 1
    fi

    log "Updating apt package index"
    sudo apt-get update

    log "Installing base dependencies"
    install_apt_pkg python3
    install_apt_pkg python3-pip
    install_apt_pkg python3-venv
    install_apt_pkg pipx
    install_apt_pkg git
    install_apt_pkg curl
    install_apt_pkg jq
    install_apt_pkg make
    install_apt_pkg gcc
    install_apt_pkg parallel

    if ! need_cmd go; then
        install_apt_pkg golang-go
    else
        ok "go already installed"
    fi

    ensure_path
    install_python_dependencies
    install_wordlists

    install_massdns
    install_projectdiscovery_tools
    install_assetfinder
    install_waybackurls
    install_ffuf

    # Optional Python tools
    install_altdns || true
    install_arjun || true

    print_summary

    ok "Installation finished. The machine did not explode, which is always encouraging."
}

main "$@"
