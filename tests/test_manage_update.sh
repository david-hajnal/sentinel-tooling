#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANAGE="${REPO_ROOT}/scripts/manage.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"

    if [[ "$haystack" != *"$needle"* ]]; then
        fail "${message}: expected to find '${needle}'"
    fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN_DIR="${TMP_DIR}/bin"
mkdir -p "${FAKE_BIN_DIR}"

cat > "${FAKE_BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "${TEST_SYSTEMCTL_LOG}"

normalize_unit() {
    local unit="${1:-}"
    unit="${unit%.service}"
    printf '%s\n' "$unit"
}

cmd="${1:-}"
shift || true

case "$cmd" in
    cat)
        unit="$(normalize_unit "${1:-}")"
        [[ -f "${TEST_SYSTEMD_UNIT_DIR}/${unit}.service" ]]
        ;;
    is-enabled)
        unit="$(normalize_unit "${1:-}")"
        [[ -f "${TEST_SYSTEMD_STATE_DIR}/enabled/${unit}" ]]
        ;;
    is-active)
        if [[ "${1:-}" == "--quiet" ]]; then
            shift
        fi
        unit="$(normalize_unit "${1:-}")"
        [[ -f "${TEST_SYSTEMD_STATE_DIR}/active/${unit}" ]]
        ;;
    enable)
        unit="$(normalize_unit "${1:-}")"
        mkdir -p "${TEST_SYSTEMD_STATE_DIR}/enabled"
        touch "${TEST_SYSTEMD_STATE_DIR}/enabled/${unit}"
        ;;
    start|restart)
        unit="$(normalize_unit "${1:-}")"
        mkdir -p "${TEST_SYSTEMD_STATE_DIR}/active"
        touch "${TEST_SYSTEMD_STATE_DIR}/active/${unit}"
        ;;
    stop|disable|daemon-reload)
        ;;
    *)
        echo "unexpected systemctl invocation: ${cmd} $*" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${FAKE_BIN_DIR}/systemctl"

MANAGE_LIB="${TMP_DIR}/manage-lib.sh"
sed '/^# Main command dispatcher/,$d' "${MANAGE}" > "${MANAGE_LIB}"
# shellcheck disable=SC1090
source "${MANAGE_LIB}"

check_root() {
    :
}

update_install_manage_script() {
    :
}

update_detect_arch() {
    echo "armv7"
}

update_download_and_verify() {
    local _arch="$1"
    local version="$2"
    UPDATE_RESOLVED_VERSION="${version#v}"
}

update_create_backup_binary() {
    log_warn "No current binary to back up (fresh install)"
}

update_install_new_binary_to() {
    local _new_binary="$1"
    local _target="$2"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${AGENT_BIN}"
    chmod 755 "${AGENT_BIN}"
}

SCENARIO_DIR="${TMP_DIR}/fresh-install"
CONFIG_DIR="${SCENARIO_DIR}/etc/sentinel_rtp_cam"
SERVER_CONFIG_JSON="${CONFIG_DIR}/server.json"
CAMERA_CONFIG_JSON="${CONFIG_DIR}/camera.json"
VERSION_FILE="${CONFIG_DIR}/firmware-version"
CLIPS_DIR="${SCENARIO_DIR}/var/lib/sentinel_rtp_cam/clips"
AGENT_BIN="${SCENARIO_DIR}/usr/local/bin/${SERVICE_NAME}"
AGENT_SERVICE_FILE="${SCENARIO_DIR}/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_BIN_DIR="$(dirname "${AGENT_BIN}")"
SYSTEMD_UNIT_DIR="$(dirname "${AGENT_SERVICE_FILE}")"
TLS_DIR="${CONFIG_DIR}/tls"
TLS_CA_CERT="${CONFIG_DIR}/ca.crt"
TLS_SERVER_CERT="${CONFIG_DIR}/server.crt"
TLS_SERVER_KEY="${CONFIG_DIR}/server.key"
TLS_AUTH_JSON="${TLS_DIR}/auth.json"

mkdir -p \
    "${CONFIG_DIR}" \
    "${INSTALL_BIN_DIR}" \
    "${SYSTEMD_UNIT_DIR}" \
    "${SCENARIO_DIR}/systemd-state/enabled" \
    "${SCENARIO_DIR}/systemd-state/active"

SYSTEMCTL_LOG="${SCENARIO_DIR}/systemctl.log"
: > "${SYSTEMCTL_LOG}"
export TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"
export TEST_SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR}"
export TEST_SYSTEMD_STATE_DIR="${SCENARIO_DIR}/systemd-state"
export PATH="${FAKE_BIN_DIR}:$PATH"

OUTPUT_FILE="${SCENARIO_DIR}/update.log"
set +e
cmd_update update latest >"${OUTPUT_FILE}" 2>&1
UPDATE_STATUS=$?
set -e
if [[ "${UPDATE_STATUS}" -ne 0 ]]; then
    cat "${OUTPUT_FILE}" >&2
    fail "cmd_update should support a fresh install"
fi

UPDATE_OUTPUT="$(cat "${OUTPUT_FILE}")"

[[ -x "${AGENT_BIN}" ]] || fail "update should install sentinel-agent on a blank host"
[[ -f "${AGENT_SERVICE_FILE}" ]] || fail "update should create sentinel-agent.service on a blank host"
assert_contains "${UPDATE_OUTPUT}" "No current binary to back up (fresh install)" "fresh install should not require an existing binary"
assert_contains "${UPDATE_OUTPUT}" "Update installed; not starting services" "fresh install should finish successfully"

echo "Manage update checks passed."
