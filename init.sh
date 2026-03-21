#!/usr/bin/env bash
# Sentinel Tooling bootstrap: installs sentinel-manage and sentinel-firmware-update.

set -euo pipefail

REPO="${SENTINEL_TOOLING_REPO:-david-hajnal/sentinel-tooling}"
BRANCH="${SENTINEL_TOOLING_BRANCH:-main}"
INSTALL_DIR="${SENTINEL_MANAGE_INSTALL_DIR:-/usr/local/bin}"
DEST="${SENTINEL_MANAGE_DEST:-${INSTALL_DIR}/sentinel-manage}"
FIRMWARE_DEST="${SENTINEL_FIRMWARE_UPDATER_DEST:-${INSTALL_DIR}/sentinel-firmware-update}"
MANAGE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts/manage.sh"
FIRMWARE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts/sentinel-firmware-update"

log() {
    echo "[sentinel-init] $*"
}

ensure_writable() {
    if [[ -w "$INSTALL_DIR" ]]; then
        return 0
    fi
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    log "Install directory not writable: $INSTALL_DIR"
    log "Re-run with sudo, or set SENTINEL_MANAGE_INSTALL_DIR to a writable path."
    exit 1
}

install_script() {
    local url="$1"
    local dest="$2"
    local label="$3"

    ensure_writable
    mkdir -p "$INSTALL_DIR"

    local tmp
    tmp="$(mktemp)"
    if ! curl -fsSL "$url" -o "$tmp"; then
        log "Failed to download: $url"
        rm -f "$tmp"
        exit 1
    fi

    chmod 755 "$tmp"
    mv -f "$tmp" "$dest"
    chmod 755 "$dest"

    log "Installed $label to $dest"
}

install_script "$MANAGE_URL" "$DEST" "sentinel-manage"
install_script "$FIRMWARE_URL" "$FIRMWARE_DEST" "sentinel-firmware-update"

if [[ -x "$DEST" ]]; then
    log "Starting sentinel-manage init..."
    "$DEST" init
else
    log "sentinel-manage not found at $DEST; skipping init"
fi
