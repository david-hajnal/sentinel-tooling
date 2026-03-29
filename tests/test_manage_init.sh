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

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"

    if [[ "$haystack" == *"$needle"* ]]; then
        fail "${message}: did not expect to find '${needle}'"
    fi
}

assert_exists() {
    local path="$1"
    local message="$2"

    if [[ ! -e "$path" ]]; then
        fail "${message}: missing ${path}"
    fi
}

assert_not_exists() {
    local path="$1"
    local message="$2"

    if [[ -e "$path" ]]; then
        fail "${message}: unexpected ${path}"
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
    disable)
        unit="$(normalize_unit "${1:-}")"
        rm -f "${TEST_SYSTEMD_STATE_DIR}/enabled/${unit}"
        ;;
    start|restart)
        unit="$(normalize_unit "${1:-}")"
        mkdir -p "${TEST_SYSTEMD_STATE_DIR}/active"
        touch "${TEST_SYSTEMD_STATE_DIR}/active/${unit}"
        ;;
    stop)
        unit="$(normalize_unit "${1:-}")"
        rm -f "${TEST_SYSTEMD_STATE_DIR}/active/${unit}"
        ;;
    daemon-reload)
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
: "${SERVICE_NAME:?failed to load manage helpers}"

check_root() {
    :
}

ORIGINAL_PATH="$PATH"

setup_scenario() {
    local name="$1"
    SCENARIO_DIR="${TMP_DIR}/${name}"
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
        "${SCENARIO_DIR}/etc/systemd/system" \
        "${SCENARIO_DIR}/systemd-state/enabled" \
        "${SCENARIO_DIR}/systemd-state/active" \
        "$(dirname "${AGENT_BIN}")"

    cat > "${AGENT_BIN}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${AGENT_BIN}"

    cat > "${SCENARIO_DIR}/etc/systemd/system/sentinel_rtp_cam.service" <<'EOF'
[Unit]
Description=Legacy service
EOF
    cat > "${SCENARIO_DIR}/etc/systemd/system/sentinel_rtp_cam_forward.service" <<'EOF'
[Unit]
Description=Legacy forward service
EOF
    touch "${SCENARIO_DIR}/usr/local/bin/sentinel_rtp_cam"
    touch "${SCENARIO_DIR}/usr/local/bin/sentinel_rtp_cam_forward"
    touch "${SCENARIO_DIR}/usr/local/bin/agent_forward"

    SYSTEMCTL_LOG="${SCENARIO_DIR}/systemctl.log"
    : > "${SYSTEMCTL_LOG}"
    export TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"
    export TEST_SYSTEMD_UNIT_DIR="${SCENARIO_DIR}/etc/systemd/system"
    export TEST_SYSTEMD_STATE_DIR="${SCENARIO_DIR}/systemd-state"
    export PATH="${FAKE_BIN_DIR}:${ORIGINAL_PATH}"
}

run_init() {
    local output_file="${SCENARIO_DIR}/init.log"
    if ! printf '\n\n\n\n\n\n' | cmd_init >"${output_file}" 2>&1; then
        cat "${output_file}" >&2
        fail "cmd_init failed for ${SCENARIO_DIR}"
    fi
    INIT_OUTPUT="$(cat "${output_file}")"
    SYSTEMCTL_OUTPUT="$(cat "${SYSTEMCTL_LOG}")"
}

setup_scenario "legacy-active"
touch "${TEST_SYSTEMD_STATE_DIR}/enabled/sentinel_rtp_cam"
touch "${TEST_SYSTEMD_STATE_DIR}/active/sentinel_rtp_cam"

run_init

assert_exists "${AGENT_SERVICE_FILE}" "init should create agent service"
assert_contains "${SYSTEMCTL_OUTPUT}" "daemon-reload" "agent service creation should reload systemd"
assert_contains "${SYSTEMCTL_OUTPUT}" "stop sentinel_rtp_cam" "init should stop the legacy service"
assert_contains "${SYSTEMCTL_OUTPUT}" "disable sentinel_rtp_cam" "init should disable the legacy service"
assert_contains "${SYSTEMCTL_OUTPUT}" "enable ${SERVICE_NAME}" "init should enable the agent service"
assert_contains "${SYSTEMCTL_OUTPUT}" "start ${SERVICE_NAME}" "init should start the agent service when the legacy service was running"
assert_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME}" "agent service should remain enabled"
assert_exists "${TEST_SYSTEMD_STATE_DIR}/active/${SERVICE_NAME}" "agent service should be active after migration"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/sentinel_rtp_cam" "legacy service should no longer be enabled"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/active/sentinel_rtp_cam" "legacy service should no longer be active"
assert_not_exists "${SCENARIO_DIR}/etc/systemd/system/sentinel_rtp_cam.service" "legacy service file should be removed"
assert_not_exists "${SCENARIO_DIR}/etc/systemd/system/sentinel_rtp_cam_forward.service" "legacy forward service file should be removed"
assert_not_exists "${SCENARIO_DIR}/usr/local/bin/sentinel_rtp_cam" "legacy binary should be removed"
assert_not_exists "${SCENARIO_DIR}/usr/local/bin/sentinel_rtp_cam_forward" "legacy forward binary should be removed"
assert_not_exists "${SCENARIO_DIR}/usr/local/bin/agent_forward" "legacy agent_forward binary should be removed"

setup_scenario "legacy-stopped"
touch "${TEST_SYSTEMD_STATE_DIR}/enabled/sentinel_rtp_cam"

run_init

assert_exists "${AGENT_SERVICE_FILE}" "init should create agent service when missing"
assert_contains "${SYSTEMCTL_OUTPUT}" "disable sentinel_rtp_cam" "init should disable the legacy service even when stopped"
assert_contains "${SYSTEMCTL_OUTPUT}" "enable ${SERVICE_NAME}" "init should enable the agent service for the next boot"
assert_not_contains "${SYSTEMCTL_OUTPUT}" "start ${SERVICE_NAME}" "init should not start the agent service on a stopped host"
assert_not_contains "${SYSTEMCTL_OUTPUT}" "restart ${SERVICE_NAME}" "init should leave a stopped host stopped"
assert_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME}" "agent service should be enabled after init"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/active/${SERVICE_NAME}" "agent service should stay stopped when no agent was running"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/sentinel_rtp_cam" "legacy service should be disabled after init"

echo "Manage init checks passed."
