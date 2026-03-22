#!/bin/sh
set -eu

REPO="${SENTINEL_TOOLING_REPO:-david-hajnal/sentinel-tooling}"
BRANCH="${SENTINEL_TOOLING_BRANCH:-main}"
INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-/usr/local/bin}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
STATE_DIR="${STATE_DIR:-/var/lib/sentinel_rtp_cam/firmware-updater}"
REQUEST_DIR="${STATE_DIR}/requests"
RESULT_DIR="${STATE_DIR}/results"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"

RAW_BASE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
MANAGE_URL="${RAW_BASE_URL}/scripts/manage.sh"
WRAPPER_URL="${RAW_BASE_URL}/scripts/sentinel-firmware-update"
DISPATCH_URL="${RAW_BASE_URL}/scripts/sentinel-firmware-update-dispatch"
SERVICE_TEMPLATE_URL="${RAW_BASE_URL}/systemd/sentinel-firmware-update-dispatch.service.in"
PATH_TEMPLATE_URL="${RAW_BASE_URL}/systemd/sentinel-firmware-update-dispatch.path.in"

MANAGE_DEST="${INSTALL_BIN_DIR}/sentinel-manage"
WRAPPER_DEST="${INSTALL_BIN_DIR}/sentinel-firmware-update"
DISPATCH_DEST="${INSTALL_BIN_DIR}/sentinel-firmware-update-dispatch"
SERVICE_DEST="${SYSTEMD_DIR}/sentinel-firmware-update-dispatch.service"
PATH_DEST="${SYSTEMD_DIR}/sentinel-firmware-update-dispatch.path"

log() {
    echo "[sentinel-firmware-updater-install] $*"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "This installer must run as root."
        exit 1
    fi
}

require_sentinel_user() {
    if ! id sentinel >/dev/null 2>&1; then
        log "sentinel user is missing; install the agent service first."
        exit 1
    fi
}

fetch_file() {
    fetch_url="$1"
    fetch_dest="$2"
    fetch_tmp="$(mktemp)"
    if ! curl -fsSL "$fetch_url" -o "$fetch_tmp"; then
        log "Failed to download: $fetch_url"
        rm -f "$fetch_tmp"
        exit 1
    fi
    mv -f "$fetch_tmp" "$fetch_dest"
}

fetch_script() {
    fetch_script_url="$1"
    fetch_script_dest="$2"
    mkdir -p "$INSTALL_BIN_DIR"
    fetch_file "$fetch_script_url" "$fetch_script_dest"
    chmod 755 "$fetch_script_dest"
}

render_unit_template() {
    render_template_url="$1"
    render_dest="$2"
    render_tmp="$(mktemp)"
    fetch_file "$render_template_url" "$render_tmp"
    sed \
        -e "s|@INSTALL_BIN_DIR@|${INSTALL_BIN_DIR}|g" \
        -e "s|@STATE_DIR@|${STATE_DIR}|g" \
        "$render_tmp" > "${render_tmp}.rendered"
    mkdir -p "$SYSTEMD_DIR"
    mv -f "${render_tmp}.rendered" "$render_dest"
    rm -f "$render_tmp"
    chmod 644 "$render_dest"
}

prepare_state_dirs() {
    mkdir -p "$STATE_DIR" "$REQUEST_DIR" "$RESULT_DIR"
    chmod 2775 "$STATE_DIR" "$REQUEST_DIR" "$RESULT_DIR"
    chown root:sentinel "$STATE_DIR" "$REQUEST_DIR" "$RESULT_DIR"
    touch "${STATE_DIR}/dispatch.lock"
    chmod 664 "${STATE_DIR}/dispatch.lock"
    chown root:sentinel "${STATE_DIR}/dispatch.lock"
}

enable_units() {
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" enable --now sentinel-firmware-update-dispatch.path
}

require_root
require_sentinel_user

fetch_script "$MANAGE_URL" "$MANAGE_DEST"
fetch_script "$WRAPPER_URL" "$WRAPPER_DEST"
fetch_script "$DISPATCH_URL" "$DISPATCH_DEST"
render_unit_template "$SERVICE_TEMPLATE_URL" "$SERVICE_DEST"
render_unit_template "$PATH_TEMPLATE_URL" "$PATH_DEST"
prepare_state_dirs
enable_units

log "Installed managed firmware updater support."
log "Wrapper: $WRAPPER_DEST"
log "Dispatcher: $DISPATCH_DEST"
log "State directory: $STATE_DIR"
