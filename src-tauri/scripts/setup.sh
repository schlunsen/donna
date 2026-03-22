#!/usr/bin/env bash
set -euo pipefail

# Donna Desktop — Development Setup Script
# Installs all prerequisites for building the Tauri desktop app.

echo "🔧 Donna Desktop — Development Setup"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 found: $($1 --version 2>/dev/null | head -1)"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 not found"
        return 1
    fi
}

echo "Checking prerequisites..."
echo ""

# Node.js
if ! check node; then
    echo -e "  ${YELLOW}→${NC} Install Node.js 22+: https://nodejs.org"
    exit 1
fi

# Rust
if ! check rustc; then
    echo -e "  ${YELLOW}→${NC} Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo -e "  ${GREEN}✓${NC} Rust installed"
fi

# Cargo
check cargo || exit 1

# Tauri CLI
if ! cargo install --list 2>/dev/null | grep -q "tauri-cli"; then
    echo -e "  ${YELLOW}→${NC} Installing Tauri CLI..."
    cargo install tauri-cli --version "^2"
    echo -e "  ${GREEN}✓${NC} Tauri CLI installed"
else
    echo -e "  ${GREEN}✓${NC} Tauri CLI already installed"
fi

# Docker
if ! check docker; then
    echo -e "  ${YELLOW}→${NC} Install Docker Desktop: https://www.docker.com/products/docker-desktop"
    echo -e "  ${YELLOW}  Docker is required for Temporal server and security tools${NC}"
fi

# Platform-specific dependencies
echo ""
echo "Checking platform dependencies..."

case "$(uname -s)" in
    Darwin)
        echo -e "  ${GREEN}✓${NC} macOS — Xcode command line tools required"
        if ! xcode-select -p &>/dev/null; then
            echo -e "  ${YELLOW}→${NC} Installing Xcode command line tools..."
            xcode-select --install
        fi
        ;;
    Linux)
        echo -e "  Checking Linux dependencies..."
        MISSING=""

        # Check for required packages
        for pkg in libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev; do
            if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
                MISSING="$MISSING $pkg"
            fi
        done

        if [ -n "$MISSING" ]; then
            echo -e "  ${YELLOW}→${NC} Installing missing packages:$MISSING"
            sudo apt-get update
            sudo apt-get install -y $MISSING
        else
            echo -e "  ${GREEN}✓${NC} All Linux dependencies installed"
        fi
        ;;
esac

# Install Node dependencies
echo ""
echo "Installing Node.js dependencies..."
npm ci
cd dashboard && npm ci && cd ..

echo ""
echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. npm run tauri dev      — Start in development mode"
echo "  2. npm run tauri build    — Build for distribution"
echo "  3. npm run tauri:build-sidecars — Build sidecar binaries"
echo ""
