#!/usr/bin/env bash
# Sentinel bootstrap installer: installs sentinel-manage, sentinel-agent, and firmware updater support.

set -euo pipefail

REPO="${SENTINEL_TOOLING_REPO:-david-hajnal/sentinel-tooling}"
BRANCH="${SENTINEL_TOOLING_BRANCH:-main}"
INSTALL_DIR="${SENTINEL_MANAGE_INSTALL_DIR:-/usr/local/bin}"
MANAGE_DEST="${SENTINEL_MANAGE_DEST:-${INSTALL_DIR}/sentinel-manage}"
RAW_BASE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
MANAGE_URL="${RAW_BASE_URL}/scripts/manage.sh"
FIRMWARE_INSTALLER_URL="${RAW_BASE_URL}/scripts/install-firmware-updater.sh"
AGENT_VERSION="${SENTINEL_AGENT_VERSION:-latest}"
START_AFTER_INSTALL="${SENTINEL_START_AFTER_INSTALL:-0}"

log() {
    echo "[sentinel-init] $*"
}

warn() {
    echo "[sentinel-init] WARN: $*" >&2
}

die() {
    echo "[sentinel-init] ERROR: $*" >&2
    exit 1
}

require_root() {
    if [[ "${SENTINEL_BOOTSTRAP_SKIP_ROOT_CHECK:-0}" == "1" ]]; then
        return 0
    fi
    if [[ $EUID -ne 0 ]]; then
        die "Run this installer with sudo."
    fi
}

download_to() {
    local url="$1"
    local dest="$2"
    local tmp
    tmp="$(mktemp)"
    if ! curl -fsSL "$url" -o "$tmp"; then
        rm -f "$tmp"
        die "Failed to download: $url"
    fi
    mv -f "$tmp" "$dest"
}

install_manage() {
    mkdir -p "$INSTALL_DIR"
    local tmp
    tmp="$(mktemp)"
    download_to "$MANAGE_URL" "$tmp"
    chmod 755 "$tmp"
    install -m 755 "$tmp" "$MANAGE_DEST"
    rm -f "$tmp"
    log "Installed sentinel-manage to $MANAGE_DEST"
}

install_firmware_support() {
    local installer
    installer="$(mktemp)"
    download_to "$FIRMWARE_INSTALLER_URL" "$installer"
    chmod 755 "$installer"
    if ! "$installer"; then
        rm -f "$installer"
        die "Failed to install managed firmware updater support"
    fi
    rm -f "$installer"
}

main() {
    require_root
    install_manage

    log "Installing sentinel-agent ${AGENT_VERSION}..."
    "$MANAGE_DEST" update "$AGENT_VERSION"

    log "Installing managed firmware updater support..."
    install_firmware_support

    if [[ "$START_AFTER_INSTALL" == "1" ]]; then
        log "Starting sentinel-agent..."
        "$MANAGE_DEST" start
    else
        log "Bootstrap install complete. Next step: sudo sentinel-manage init"
    fi
}

main "$@"
