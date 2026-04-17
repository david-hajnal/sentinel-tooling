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

cat > "${FAKE_BIN_DIR}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 22
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

cat > "${FAKE_BIN_DIR}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output_path=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            output_path="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ "${TEST_CURL_EXIT_CODE:-0}" != "0" ]]; then
    exit "${TEST_CURL_EXIT_CODE}"
fi

if [[ -z "${output_path}" ]]; then
    echo "missing -o argument" >&2
    exit 1
fi

cp "${TEST_CURL_RESPONSE_FILE}" "${output_path}"
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

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

    mkdir -p "${CONFIG_DIR}"
    cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://admin.example.test:8443",
    "bearer_token": "token-123",
    "enabled": true
  }
}
EOF

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
    export TEST_ACTION_LOG="${SYSTEMCTL_LOG}"
    export TEST_SYSTEMD_UNIT_DIR="${SCENARIO_DIR}/etc/systemd/system"
    export TEST_SYSTEMD_STATE_DIR="${SCENARIO_DIR}/systemd-state"
    export PATH="${FAKE_BIN_DIR}:${ORIGINAL_PATH}"
}

run_init() {
    local output_file="${SCENARIO_DIR}/init.log"
    local input="${INIT_INPUT:-$DEFAULT_INIT_INPUT}"
    if ! printf '%s' "$input" | cmd_init >"${output_file}" 2>&1; then
        cat "${output_file}" >&2
        fail "cmd_init failed for ${SCENARIO_DIR}"
    fi
    INIT_OUTPUT="$(cat "${output_file}")"
    SYSTEMCTL_OUTPUT="$(cat "${SYSTEMCTL_LOG}")"
}

DEFAULT_INIT_INPUT=$'\n\n\n\n\n\n'

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
assert_contains "${SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${SERVER_CONFIG_JSON}" "init should normalize server config ownership"
assert_contains "${SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${CAMERA_CONFIG_JSON}" "init should normalize camera config ownership"
assert_mode "${SERVER_CONFIG_JSON}" "600"
assert_mode "${CAMERA_CONFIG_JSON}" "600"

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

setup_scenario "config-pull-raw-payload"
mkdir -p "${CONFIG_DIR}"
cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://example.test:443",
    "bearer_token": "device-token"
  }
}
EOF
cat > "${CAMERA_CONFIG_JSON}" <<'EOF'
{
  "existing": true
}
EOF
RAW_CONFIG_RESPONSE="${SCENARIO_DIR}/config-response.json"
cat > "${RAW_CONFIG_RESPONSE}" <<'EOF'
{
  "server": {
    "bearer_token": "remote-token"
  },
  "cameras": [
    {
      "camera_id": "cam-1",
      "user": "alice"
    }
  ]
}
EOF
export TEST_CURL_RESPONSE_FILE="${RAW_CONFIG_RESPONSE}"
export TEST_CURL_EXIT_CODE=0
PULL_OUTPUT="$(pull_remote_config "https://example.test:443" "device-token" 2>&1 || true)"
assert_contains "${PULL_OUTPUT}" "Pulled camera config from server." "raw config payload should be accepted"
CAMERA_USER="$(python3 - "${CAMERA_CONFIG_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

print(data["cameras"][0]["user"])
PY
)"
assert_contains "${CAMERA_USER}" "alice" "raw payload should update camera config"
SERVER_TOKEN="$(python3 - "${SERVER_CONFIG_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

print(data["server"]["bearer_token"])
PY
)"
assert_contains "${SERVER_TOKEN}" "remote-token" "raw payload should update non-null server fields"

setup_scenario "config-pull-preserves-local-server-credentials-on-null"
mkdir -p "${CONFIG_DIR}"
cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://example.test:443",
    "bearer_token": "device-token",
    "enabled": true
  }
}
EOF
cat > "${CAMERA_CONFIG_JSON}" <<'EOF'
{
  "existing": true
}
EOF
NULL_SERVER_RESPONSE="${SCENARIO_DIR}/config-response-null-server.json"
cat > "${NULL_SERVER_RESPONSE}" <<'EOF'
{
  "server": {
    "base_url": null,
    "bearer_token": null,
    "enabled": null
  },
  "cameras": [
    {
      "camera_id": "cam-1",
      "user": "alice"
    }
  ]
}
EOF
export TEST_CURL_RESPONSE_FILE="${NULL_SERVER_RESPONSE}"
export TEST_CURL_EXIT_CODE=0
NULL_PULL_OUTPUT="$(pull_remote_config "https://example.test:443" "device-token" 2>&1 || true)"
assert_contains "${NULL_PULL_OUTPUT}" "Pulled camera config from server." "null server payload should still update camera config"
NULL_SERVER_STATE="$(python3 - "${SERVER_CONFIG_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

print(data["server"]["base_url"])
print(data["server"]["bearer_token"])
PY
)"
assert_contains "${NULL_SERVER_STATE}" "https://example.test:443" "null server payload should preserve local base_url"
assert_contains "${NULL_SERVER_STATE}" "device-token" "null server payload should preserve local bearer token"

setup_scenario "config-pull-ignores-empty-string-server-overrides"
mkdir -p "${CONFIG_DIR}"
cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://example.test:443",
    "bearer_token": "device-token",
    "enabled": true
  }
}
EOF
cat > "${CAMERA_CONFIG_JSON}" <<'EOF'
{
  "existing": true
}
EOF
EMPTY_SERVER_RESPONSE="${SCENARIO_DIR}/config-response-empty-server.json"
cat > "${EMPTY_SERVER_RESPONSE}" <<'EOF'
{
  "server": {
    "base_url": "",
    "bearer_token": ""
  },
  "cameras": [
    {
      "camera_id": "cam-1",
      "user": "alice"
    }
  ]
}
EOF
export TEST_CURL_RESPONSE_FILE="${EMPTY_SERVER_RESPONSE}"
export TEST_CURL_EXIT_CODE=0
EMPTY_PULL_OUTPUT="$(pull_remote_config "https://example.test:443" "device-token" 2>&1 || true)"
assert_contains "${EMPTY_PULL_OUTPUT}" "Pulled camera config from server." "empty-string server payload should still update camera config"
EMPTY_SERVER_STATE="$(python3 - "${SERVER_CONFIG_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)

print(data["server"]["base_url"])
print(data["server"]["bearer_token"])
PY
)"
assert_contains "${EMPTY_SERVER_STATE}" "https://example.test:443" "empty-string server payload should preserve local base_url"
assert_contains "${EMPTY_SERVER_STATE}" "device-token" "empty-string server payload should preserve local bearer token"

setup_scenario "config-pull-invalid-json"
mkdir -p "${CONFIG_DIR}"
cat > "${SERVER_CONFIG_JSON}" <<'EOF'
{
  "server": {
    "base_url": "https://example.test:443",
    "bearer_token": "device-token"
  }
}
EOF
cat > "${CAMERA_CONFIG_JSON}" <<'EOF'
{}
EOF
INVALID_CONFIG_RESPONSE="${SCENARIO_DIR}/config-response.txt"
cat > "${INVALID_CONFIG_RESPONSE}" <<'EOF'
<html><body>login required</body></html>
EOF
export TEST_CURL_RESPONSE_FILE="${INVALID_CONFIG_RESPONSE}"
export TEST_CURL_EXIT_CODE=0
INVALID_PULL_OUTPUT="$(pull_remote_config "https://example.test:443" "device-token" 2>&1 || true)"
assert_contains "${INVALID_PULL_OUTPUT}" "Invalid JSON payload" "invalid payload should report parse failure"
assert_contains "${INVALID_PULL_OUTPUT}" "Response preview: <html><body>login required</body></html>" "invalid payload should include response preview"
assert_contains "${INVALID_PULL_OUTPUT}" "Failed to parse config payload from server." "invalid payload should preserve high-level warning"

setup_scenario "fresh-config-files-get-normalized"
rm -f "${SERVER_CONFIG_JSON}" "${CAMERA_CONFIG_JSON}"
export SENTINEL_SERVER_BASE_URL="https://sentinel.example:443"
INIT_INPUT=$'\n\n\n\n\nfresh-token\n'

run_init

assert_exists "${SERVER_CONFIG_JSON}" "fresh init should create server config"
assert_exists "${CAMERA_CONFIG_JSON}" "fresh init should create camera config"
assert_contains "${SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${SERVER_CONFIG_JSON}" "fresh init should normalize server config ownership"
assert_contains "${SYSTEMCTL_OUTPUT}" "chown sentinel:sentinel ${CAMERA_CONFIG_JSON}" "fresh init should normalize camera config ownership"
assert_mode "${SERVER_CONFIG_JSON}" "600"
assert_mode "${CAMERA_CONFIG_JSON}" "600"

echo "Manage init checks passed."
