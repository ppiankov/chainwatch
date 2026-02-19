#!/usr/bin/env bash
# nullbot installer — installs nullbot + chainwatch in one step
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install-nullbot.sh | bash
#
# Options:
#   --system    Install to /usr/local/bin (requires sudo)
#   --help      Show usage
#
# To inspect before running:
#   curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install-nullbot.sh -o install-nullbot.sh
#   less install-nullbot.sh
#   bash install-nullbot.sh
set -euo pipefail

REPO="ppiankov/chainwatch"
INSTALL_DIR="${HOME}/.local/bin"
SYSTEM_MODE=false

usage() {
    cat <<EOF
Usage: install-nullbot.sh [OPTIONS]

Install nullbot — the bot that behaves — with chainwatch pre-wired.

Downloads both nullbot (LLM agent) and chainwatch (runtime guardrail),
configures chainwatch, and verifies the installation.

Options:
  --system    Install to /usr/local/bin (requires sudo)
  --help      Show this help

Default: installs to ~/.local/bin (no root required).

After install:
  nullbot run "check disk usage"           # local ollama
  GROQ_API_KEY=xxx nullbot run "audit"     # groq cloud
  nullbot run --dry-run "free disk space"  # plan only
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

download_and_verify() {
    local name="$1"
    local binary_name="${name}-${OS}-${ARCH}"
    local download_url="https://github.com/${REPO}/releases/download/v${VERSION}/${binary_name}"

    echo "Downloading ${name} v${VERSION} (${OS}/${ARCH})..."
    curl -fsSL "$download_url" -o "${TMPDIR_INSTALL}/${name}" || die "download failed: ${download_url}"

    # Verify checksum if checksums file is available.
    if [ -f "${TMPDIR_INSTALL}/checksums.txt" ]; then
        local expected
        expected=$(grep "$binary_name" "${TMPDIR_INSTALL}/checksums.txt" | awk '{print $1}')
        if [ -n "$expected" ]; then
            local actual
            if command -v sha256sum >/dev/null 2>&1; then
                actual=$(sha256sum "${TMPDIR_INSTALL}/${name}" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                actual=$(shasum -a 256 "${TMPDIR_INSTALL}/${name}" | awk '{print $1}')
            fi
            if [ -n "${actual:-}" ] && [ "$actual" != "$expected" ]; then
                die "${name} checksum mismatch: expected ${expected}, got ${actual}"
            fi
            echo "  ${name}: checksum verified"
        fi
    fi

    chmod +x "${TMPDIR_INSTALL}/${name}"
}

install_binaries() {
    TMPDIR_INSTALL="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

    local checksums_url="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"
    curl -fsSL "$checksums_url" -o "${TMPDIR_INSTALL}/checksums.txt" 2>/dev/null || true

    download_and_verify "chainwatch"
    download_and_verify "nullbot"

    if [ "$SYSTEM_MODE" = true ]; then
        INSTALL_DIR="/usr/local/bin"
        echo ""
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo mv "${TMPDIR_INSTALL}/chainwatch" "${INSTALL_DIR}/chainwatch"
        sudo mv "${TMPDIR_INSTALL}/nullbot" "${INSTALL_DIR}/nullbot"
    else
        mkdir -p "$INSTALL_DIR"
        mv "${TMPDIR_INSTALL}/chainwatch" "${INSTALL_DIR}/chainwatch"
        mv "${TMPDIR_INSTALL}/nullbot" "${INSTALL_DIR}/nullbot"
    fi

    echo ""
    echo "Installed: ${INSTALL_DIR}/chainwatch"
    echo "Installed: ${INSTALL_DIR}/nullbot"
}

run_init() {
    local cw="${INSTALL_DIR}/chainwatch"

    if [ "$SYSTEM_MODE" = true ]; then
        echo ""
        echo "Running: chainwatch init --mode system"
        sudo "$cw" init --mode system
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

print_next_steps() {
    echo ""
    echo "Ready! Try:"
    echo "  nullbot run \"check system health\""
    echo ""
    echo "Backends:"
    echo "  Local ollama (default):  nullbot run \"free disk space\""
    echo "  Groq cloud:              GROQ_API_KEY=xxx nullbot run \"audit system\""
    echo "  Any OpenAI-compatible:   nullbot run --api-url http://host/v1/chat/completions \"task\""
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
    install_binaries
    run_init
    run_doctor
    check_path
    print_next_steps
}

main "$@"
