#!/bin/bash
set -euo pipefail

# topsrv installer
# Usage: curl -fsSL https://topsrv.io/install.sh | TOPSRV_TOKEN=xxx bash
#    or: curl -fsSL https://topsrv.io/install.sh | TOPSRV_TOKEN=xxx TOPSRV_ENDPOINT=https://push.example.com/v1/write bash
#
# Environment variables:
#   VERSION          - specific version to install (default: latest)
#   INSTALL_DIR      - binary install path (default: /usr/local/bin)
#   TOPSRV_TOKEN     - push token
#   TOPSRV_ENDPOINT  - push endpoint (default: https://push.topsrv.io/v1/write)

REPO="vmkteam/topsrv"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="/etc/topsrv"
SPOOL_DIR="/var/lib/topsrv/spool"
SERVICE_NAME="topsrv"

# Defaults.
TOPSRV_TOKEN="${TOPSRV_TOKEN:-}"
TOPSRV_ENDPOINT="${TOPSRV_ENDPOINT:-https://push.topsrv.io/v1/write}"

# --- Helpers ---

log() { echo "==> $*" >&2; }
err() { echo "ERROR: $*" >&2; exit 1; }

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Required command not found: $1. Please install it and retry."
    fi
}

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script requires root privileges. Please run with sudo."
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             err "Unsupported architecture: $(uname -m)" ;;
    esac
}

latest_version() {
    local url
    url=$(curl -sSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")
    echo "${url##*/v}"
}

verify_checksum() {
    local file="$1" checksums="$2" filename
    filename=$(basename "$file")

    need_cmd sha256sum || need_cmd shasum

    local expected
    expected=$(grep "  ${filename}$" "$checksums" | awk '{print $1}')
    if [ -z "$expected" ]; then
        err "Checksum not found for ${filename} in checksums.txt"
    fi

    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    fi

    if [ "$actual" != "$expected" ]; then
        err "Checksum mismatch for ${filename}: expected ${expected}, got ${actual}"
    fi

    log "Checksum verified: ${filename}"
}

# --- Main ---

need_root
need_cmd curl
need_cmd tar

OS="linux"
ARCH=$(detect_arch)

if [ "$(uname -s)" != "Linux" ]; then
    err "This installer supports Linux only. Detected OS: $(uname -s)"
fi

VERSION="${VERSION:-$(latest_version)}"

if [ -z "$VERSION" ]; then
    err "Could not determine latest version. Check https://github.com/${REPO}/releases"
fi

log "topsrv installer v${VERSION} (${OS}/${ARCH})"

# Download.
TARBALL="topsrv_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

log "Downloading ${TARBALL}..."
curl -fsSL -o "${TMPDIR}/${TARBALL}" "${BASE_URL}/${TARBALL}"
curl -fsSL -o "${TMPDIR}/checksums.txt" "${BASE_URL}/checksums.txt"

# Verify checksum.
verify_checksum "${TMPDIR}/${TARBALL}" "${TMPDIR}/checksums.txt"

# Extract and install binary.
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

log "Installing to ${INSTALL_DIR}/topsrv"
install -m 0755 "${TMPDIR}/topsrv" "${INSTALL_DIR}/topsrv"

# Verify.
INSTALLED_VERSION=$("${INSTALL_DIR}/topsrv" -version 2>&1 || true)
log "Installed: ${INSTALLED_VERSION}"

# Create config (only if not exists).
mkdir -p "$CONFIG_DIR" "$SPOOL_DIR"

if [ ! -f "${CONFIG_DIR}/topsrv.toml" ]; then
    log "Creating config: ${CONFIG_DIR}/topsrv.toml"
    cat > "${CONFIG_DIR}/topsrv.toml" <<EOF
[Push]
Endpoint = "${TOPSRV_ENDPOINT}"
Token    = "${TOPSRV_TOKEN}"
SpoolDir = "${SPOOL_DIR}"
EOF
else
    log "Config already exists: ${CONFIG_DIR}/topsrv.toml (not overwriting)"
fi

# Systemd service.
if command -v systemctl >/dev/null 2>&1; then
    log "Installing systemd service"
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=topsrv monitoring agent
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/topsrv -config ${CONFIG_DIR}/topsrv.toml
Restart=always
RestartSec=5
SuccessExitStatus=42
StartLimitBurst=5
StartLimitIntervalSec=120

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    log "Service started: systemctl status ${SERVICE_NAME}"
else
    log "No systemd — skipping service install"
    log "Start manually: ${INSTALL_DIR}/topsrv -config ${CONFIG_DIR}/topsrv.toml"
fi

log "Done!"
