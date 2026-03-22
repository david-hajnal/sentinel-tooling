#!/usr/bin/env bash
# Sentinel Tooling bootstrap: installs sentinel-manage.

set -euo pipefail

REPO="${SENTINEL_TOOLING_REPO:-david-hajnal/sentinel-tooling}"
BRANCH="${SENTINEL_TOOLING_BRANCH:-main}"
INSTALL_DIR="${SENTINEL_MANAGE_INSTALL_DIR:-/usr/local/bin}"
DEST="${SENTINEL_MANAGE_DEST:-${INSTALL_DIR}/sentinel-manage}"
URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts/manage.sh"

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

install_manage() {
    ensure_writable
    mkdir -p "$INSTALL_DIR"

    local tmp
    tmp="$(mktemp)"
    if ! curl -fsSL "$URL" -o "$tmp"; then
        log "Failed to download: $URL"
        rm -f "$tmp"
        exit 1
    fi

    chmod 755 "$tmp"
    mv -f "$tmp" "$DEST"
    chmod 755 "$DEST"

    log "Installed sentinel-manage to $DEST"
}

install_manage

if [[ -x "$DEST" ]]; then
    log "Starting sentinel-manage init..."
    "$DEST" init
else
    log "sentinel-manage not found at $DEST; skipping init"
fi
