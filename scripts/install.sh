#!/usr/bin/env bash
# chainwatch installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install.sh | bash
#
# Options:
#   --system    Install to /usr/local/bin (requires sudo) and enable systemd
#   --help      Show usage
#
# To inspect before running:
#   curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install.sh -o install.sh
#   less install.sh
#   bash install.sh
set -euo pipefail

REPO="ppiankov/chainwatch"
INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_MODE=false

usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Install chainwatch — runtime control plane for AI agent safety.

Options:
  --system    Install to /usr/local/bin and enable systemd template (requires sudo)
  --help      Show this help

Default: installs to ~/.local/bin (no root required).
EOF
}

die() {
    echo "error: $1" >&2
    exit 1
}

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      die "unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              die "unsupported architecture: $ARCH" ;;
    esac
}

get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION=$(curl -fsSL "$url" | grep '"tag_name"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        die "cannot determine latest version from GitHub"
    fi
}

download_binary() {
    local binary_name="chainwatch-${OS}-${ARCH}"
    local download_url="https://github.com/${REPO}/releases/download/v${VERSION}/${binary_name}"
    local checksums_url="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"

    echo "Downloading chainwatch v${VERSION} (${OS}/${ARCH})..."

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fsSL "$download_url" -o "${tmpdir}/chainwatch" || die "download failed: ${download_url}"
    curl -fsSL "$checksums_url" -o "${tmpdir}/checksums.txt" 2>/dev/null || true

    # Verify checksum if available.
    if [ -f "${tmpdir}/checksums.txt" ]; then
        local expected
        expected=$(grep "$binary_name" "${tmpdir}/checksums.txt" | awk '{print $1}')
        if [ -n "$expected" ]; then
            local actual
            if command -v sha256sum >/dev/null 2>&1; then
                actual=$(sha256sum "${tmpdir}/chainwatch" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                actual=$(shasum -a 256 "${tmpdir}/chainwatch" | awk '{print $1}')
            fi
            if [ -n "${actual:-}" ] && [ "$actual" != "$expected" ]; then
                die "checksum mismatch: expected ${expected}, got ${actual}"
            fi
            echo "Checksum verified."
        fi
    fi

    chmod +x "${tmpdir}/chainwatch"

    # Install binary.
    if [ "$SYSTEM_MODE" = true ]; then
        INSTALL_DIR="/usr/local/bin"
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo mv "${tmpdir}/chainwatch" "${INSTALL_DIR}/chainwatch"
    else
        mkdir -p "$INSTALL_DIR"
        mv "${tmpdir}/chainwatch" "${INSTALL_DIR}/chainwatch"
    fi

    echo "Installed: ${INSTALL_DIR}/chainwatch"
}

run_init() {
    local cw="${INSTALL_DIR}/chainwatch"

    if [ "$SYSTEM_MODE" = true ]; then
        echo ""
        echo "Running: chainwatch init --mode system --install-systemd"
        sudo "$cw" init --mode system --install-systemd
    else
        echo ""
        echo "Running: chainwatch init"
        "$cw" init
    fi
}

run_doctor() {
    local cw="${INSTALL_DIR}/chainwatch"
    echo ""
    "$cw" doctor || true
}

check_path() {
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        echo ""
        echo "Add to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
        echo "Add that line to ~/.bashrc or ~/.zshrc to make it permanent."
    fi
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --system) SYSTEM_MODE=true ;;
            --help|-h) usage; exit 0 ;;
            *) die "unknown option: $arg" ;;
        esac
    done

    detect_platform
    get_latest_version
    download_binary
    run_init
    run_doctor
    check_path
}

main "$@"
