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

assert_before() {
    local log_file="$1"
    local first="$2"
    local second="$3"
    local message="$4"
    local first_line
    local second_line

    first_line="$(grep -nF "$first" "$log_file" | head -n1 | cut -d: -f1 || true)"
    second_line="$(grep -nF "$second" "$log_file" | head -n1 | cut -d: -f1 || true)"

    if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
        fail "${message}: expected '${first}' before '${second}'"
    fi
}

assert_mode() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(python3 - "$path" <<'PY'
import os
import stat
import sys

mode = stat.S_IMODE(os.stat(sys.argv[1]).st_mode)
print(format(mode, "o"))
PY
)"
    if [[ "$actual" != "$expected" ]]; then
        fail "unexpected mode for ${path}: expected ${expected}, got ${actual}"
    fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN_DIR="${TMP_DIR}/bin"
mkdir -p "${FAKE_BIN_DIR}"

cat > "${FAKE_BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "${TEST_ACTION_LOG:-${TEST_SYSTEMCTL_LOG}}"

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

cat > "${FAKE_BIN_DIR}/chown" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf 'chown %s\n' "$*" >> "${TEST_ACTION_LOG:-${TEST_SYSTEMCTL_LOG}}"
EOF
chmod +x "${FAKE_BIN_DIR}/chown"

cat > "${FAKE_BIN_DIR}/useradd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
chmod +x "${FAKE_BIN_DIR}/useradd"

cat > "${FAKE_BIN_DIR}/id" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "sentinel" ]]; then
    exit 0
fi

exec /usr/bin/id "$@"
EOF
chmod +x "${FAKE_BIN_DIR}/id"

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

cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://admin.example.test:8443",
    "bearer_token": "token-123",
    "enabled": true
  }
}
EOF

cat > "${CAMERA_CONFIG_JSON}" <<'EOF'
{
  "existing": true
}
EOF

SYSTEMCTL_LOG="${SCENARIO_DIR}/systemctl.log"
: > "${SYSTEMCTL_LOG}"
export TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"
export TEST_ACTION_LOG="${SYSTEMCTL_LOG}"
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
SYSTEMCTL_OUTPUT="$(cat "${SYSTEMCTL_LOG}")"

[[ -x "${AGENT_BIN}" ]] || fail "update should install sentinel-agent on a blank host"
[[ -f "${AGENT_SERVICE_FILE}" ]] || fail "update should create sentinel-agent.service on a blank host"
assert_contains "${UPDATE_OUTPUT}" "No current binary to back up (fresh install)" "fresh install should not require an existing binary"
assert_contains "${UPDATE_OUTPUT}" "Update installed; not starting services" "fresh install should finish successfully"

assert_contains "${SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${SERVER_CONFIG_JSON}" "update should normalize server config ownership"
assert_contains "${SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${CAMERA_CONFIG_JSON}" "update should normalize camera config ownership"
assert_mode "${SERVER_CONFIG_JSON}" "600"
assert_mode "${CAMERA_CONFIG_JSON}" "600"

SCENARIO_DIR="${TMP_DIR}/update-start-repair"
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

cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://admin.example.test:8443",
    "bearer_token": "token-123",
    "enabled": true
  }
}
EOF

cat > "${CAMERA_CONFIG_JSON}" <<'EOF'
{
  "existing": true
}
EOF

cat > "${AGENT_BIN}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${AGENT_BIN}"

touch "${SCENARIO_DIR}/systemd-state/active/${SERVICE_NAME}"

SYSTEMCTL_LOG="${SCENARIO_DIR}/systemctl.log"
: > "${SYSTEMCTL_LOG}"
export TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"
export TEST_ACTION_LOG="${SYSTEMCTL_LOG}"
export TEST_SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR}"
export TEST_SYSTEMD_STATE_DIR="${SCENARIO_DIR}/systemd-state"

START_OUTPUT_FILE="${SCENARIO_DIR}/update-start.log"
set +e
cmd_update update latest --start >"${START_OUTPUT_FILE}" 2>&1
START_STATUS=$?
set -e
if [[ "${START_STATUS}" -ne 0 ]]; then
    cat "${START_OUTPUT_FILE}" >&2
    fail "cmd_update should support start-after-install"
fi

START_OUTPUT="$(cat "${START_OUTPUT_FILE}")"
START_SYSTEMCTL_OUTPUT="$(cat "${SYSTEMCTL_LOG}")"
assert_contains "${START_SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${SERVER_CONFIG_JSON}" "update start path should normalize server config ownership"
assert_contains "${START_SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${CAMERA_CONFIG_JSON}" "update start path should normalize camera config ownership"
assert_before "${SYSTEMCTL_LOG}" "chown sentinel:sentinel ${SERVER_CONFIG_JSON}" "stop sentinel-agent" "config repair should happen before restart stop/start"
assert_before "${SYSTEMCTL_LOG}" "stop sentinel-agent" "start sentinel-agent" "restart path should stop before start"
assert_mode "${SERVER_CONFIG_JSON}" "600"
assert_mode "${CAMERA_CONFIG_JSON}" "600"

echo "Manage update checks passed."
