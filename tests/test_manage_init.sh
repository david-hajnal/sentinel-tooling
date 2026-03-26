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
        if [[ "$unit" == "sentinel_rtp_cam" ]]; then
            exit 0
        fi
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
: "${SERVICE_NAME_FORWARD:?failed to load manage helpers}"

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
    FORWARD_BIN="${SCENARIO_DIR}/usr/local/bin/${SERVICE_NAME_FORWARD}"
    FORWARD_SERVICE_FILE="${SCENARIO_DIR}/etc/systemd/system/${SERVICE_NAME_FORWARD}.service"
    TLS_DIR="${CONFIG_DIR}/tls"
    TLS_CA_CERT="${CONFIG_DIR}/ca.crt"
    TLS_SERVER_CERT="${CONFIG_DIR}/server.crt"
    TLS_SERVER_KEY="${CONFIG_DIR}/server.key"
    TLS_AUTH_JSON="${TLS_DIR}/auth.json"

    mkdir -p \
        "${SCENARIO_DIR}/etc/systemd/system" \
        "${SCENARIO_DIR}/systemd-state/enabled" \
        "${SCENARIO_DIR}/systemd-state/active" \
        "$(dirname "${FORWARD_BIN}")"

    cat > "${FORWARD_BIN}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${FORWARD_BIN}"

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
touch "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME_LEGACY}"
touch "${TEST_SYSTEMD_STATE_DIR}/active/${SERVICE_NAME_LEGACY}"

run_init

assert_exists "${FORWARD_SERVICE_FILE}" "init should create forward service"
assert_contains "${SYSTEMCTL_OUTPUT}" "daemon-reload" "forward service creation should reload systemd"
assert_contains "${SYSTEMCTL_OUTPUT}" "stop ${SERVICE_NAME_LEGACY}" "init should stop the legacy service"
assert_contains "${SYSTEMCTL_OUTPUT}" "disable ${SERVICE_NAME_LEGACY}" "init should disable the legacy service"
assert_contains "${SYSTEMCTL_OUTPUT}" "enable ${SERVICE_NAME_FORWARD}" "init should enable the forward service"
assert_contains "${SYSTEMCTL_OUTPUT}" "start ${SERVICE_NAME_FORWARD}" "init should start the forward service when the legacy service was running"
assert_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME_FORWARD}" "forward service should remain enabled"
assert_exists "${TEST_SYSTEMD_STATE_DIR}/active/${SERVICE_NAME_FORWARD}" "forward service should be active after migration"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME_LEGACY}" "legacy service should no longer be enabled"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/active/${SERVICE_NAME_LEGACY}" "legacy service should no longer be active"

setup_scenario "legacy-stopped"
touch "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME_LEGACY}"

run_init

assert_exists "${FORWARD_SERVICE_FILE}" "init should create forward service when missing"
assert_contains "${SYSTEMCTL_OUTPUT}" "disable ${SERVICE_NAME_LEGACY}" "init should disable the legacy service even when stopped"
assert_contains "${SYSTEMCTL_OUTPUT}" "enable ${SERVICE_NAME_FORWARD}" "init should enable the forward service for the next boot"
assert_not_contains "${SYSTEMCTL_OUTPUT}" "start ${SERVICE_NAME_FORWARD}" "init should not start the forward service on a stopped host"
assert_not_contains "${SYSTEMCTL_OUTPUT}" "restart ${SERVICE_NAME_FORWARD}" "init should leave a stopped host stopped"
assert_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME_FORWARD}" "forward service should be enabled after init"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/active/${SERVICE_NAME_FORWARD}" "forward service should stay stopped when no agent was running"
assert_not_exists "${TEST_SYSTEMD_STATE_DIR}/enabled/${SERVICE_NAME_LEGACY}" "legacy service should be disabled after init"

echo "Manage init checks passed."
