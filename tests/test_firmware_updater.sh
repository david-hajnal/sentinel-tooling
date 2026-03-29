#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="${REPO_ROOT}/scripts/sentinel-firmware-update"
DISPATCH="${REPO_ROOT}/scripts/sentinel-firmware-update-dispatch"
INSTALLER="${REPO_ROOT}/scripts/install-firmware-updater.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local message="$3"

    if [[ "$actual" != "$expected" ]]; then
        fail "${message}: expected '${expected}', got '${actual}'"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"

    if [[ "$haystack" != *"$needle"* ]]; then
        fail "${message}: expected to find '${needle}'"
    fi
}

assert_file_eq() {
    local path="$1"
    local expected="$2"
    local message="$3"

    if [[ ! -f "$path" ]]; then
        fail "${message}: missing file ${path}"
    fi

    local actual
    actual="$(tr -d '\n' < "$path")"
    assert_eq "$actual" "$expected" "$message"
}

run_wrapper_with_dispatch() {
    local output_file="$1"
    shift

    (
        sleep 1
        "${DISPATCH}"
    ) &
    local dispatch_pid=$!

    if "${WRAPPER}" "$@" >"${output_file}" 2>&1; then
        RUN_STATUS=0
    else
        RUN_STATUS=$?
    fi

    wait "${dispatch_pid}"
    RUN_OUTPUT="$(cat "${output_file}")"
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

STATE_DIR="${TMP_DIR}/state"
REQUEST_DIR="${STATE_DIR}/requests"
RESULT_DIR="${STATE_DIR}/results"
STUB_BIN_DIR="${TMP_DIR}/bin"
MANAGE_LOG="${TMP_DIR}/manage.log"
VERSION_FILE="${TMP_DIR}/etc/sentinel_rtp_cam/firmware-version"
INSTALL_ROOT="${TMP_DIR}/install-root"
INSTALL_BIN_DIR="${INSTALL_ROOT}/usr/local/bin"
SYSTEMD_DIR="${INSTALL_ROOT}/etc/systemd/system"
INSTALL_STATE_DIR="${INSTALL_ROOT}/var/lib/sentinel_rtp_cam/firmware-updater"
SYSTEMCTL_LOG="${TMP_DIR}/systemctl.log"
SYSTEMD_RUN_LOG="${TMP_DIR}/systemd-run.log"

mkdir -p "${REQUEST_DIR}" "${RESULT_DIR}" "${STUB_BIN_DIR}"

cat > "${STUB_BIN_DIR}/sentinel-manage" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" > "${TEST_SENTINEL_MANAGE_LOG}"

if [[ "${1:-}" != "update" ]]; then
    exit 99
fi

shift
target_version=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --start)
            ;;
        *)
            target_version="$1"
            ;;
    esac
    shift
done

if [[ "${target_version}" == "latest" ]]; then
    target_version="${TEST_LATEST_RESOLVED_VERSION}"
fi

mkdir -p "$(dirname "${TEST_FIRMWARE_VERSION_FILE}")"
printf '%s\n' "${target_version}" > "${TEST_FIRMWARE_VERSION_FILE}"
EOF
chmod +x "${STUB_BIN_DIR}/sentinel-manage"

cat > "${STUB_BIN_DIR}/systemd-run" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TEST_SYSTEMD_RUN_LOG}"
EOF
chmod +x "${STUB_BIN_DIR}/systemd-run"

export PATH="${STUB_BIN_DIR}:$PATH"
export SENTINEL_FIRMWARE_UPDATER_STATE_DIR="${STATE_DIR}"
export SENTINEL_FIRMWARE_VERSION_FILE="${VERSION_FILE}"
export SENTINEL_MANAGE_CMD="${STUB_BIN_DIR}/sentinel-manage"
export TEST_SYSTEMD_RUN_LOG="${SYSTEMD_RUN_LOG}"
export TEST_SENTINEL_MANAGE_LOG="${MANAGE_LOG}"
export TEST_FIRMWARE_VERSION_FILE="${VERSION_FILE}"
export TEST_LATEST_RESOLVED_VERSION="9.9.9"

run_wrapper_with_dispatch "${TMP_DIR}/run-113.log" 1.1.3
assert_eq "${RUN_STATUS}" "0" "plain update status"
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update 1.1.3" "version mapping"
assert_file_eq "${VERSION_FILE}" "1.1.3" "firmware version file write"
assert_contains "${RUN_OUTPUT}" "Firmware update completed: 1.1.3." "success message"

run_wrapper_with_dispatch "${TMP_DIR}/run-start.log" 1.1.3 --start
assert_eq "${RUN_STATUS}" "0" "update with start status"
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update 1.1.3" "version mapping with deferred restart"
assert_contains "$(cat "${SYSTEMD_RUN_LOG}")" "restart" "restart scheduling"
assert_contains "${RUN_OUTPUT}" "Restart scheduled." "restart scheduling message"

run_wrapper_with_dispatch "${TMP_DIR}/run-latest.log" latest
assert_eq "${RUN_STATUS}" "0" "latest update status"
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update latest" "latest mapping"
assert_file_eq "${VERSION_FILE}" "9.9.9" "latest writes resolved firmware version"

run_wrapper_with_dispatch "${TMP_DIR}/run-vprefix.log" v1.1.3
assert_eq "${RUN_STATUS}" "0" "v-prefixed update status"
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update 1.1.3" "v-prefixed version normalization"

if "${WRAPPER}" --rollback >"${TMP_DIR}/rollback.log" 2>&1; then
    fail "rollback should fail"
fi
assert_contains "$(cat "${TMP_DIR}/rollback.log")" "Rollback is not supported" "rollback error"

FAKE_BIN_DIR="${TMP_DIR}/installer-bin"
mkdir -p "${FAKE_BIN_DIR}"

cat > "${FAKE_BIN_DIR}/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail

dest=""
url=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in
        -o)
            dest="\$2"
            shift 2
            ;;
        -f|-s|-S|-L|-fsSL)
            shift
            ;;
        *)
            url="\$1"
            shift
            ;;
    esac
done

case "\${url}" in
    */scripts/manage.sh)
        cp "${REPO_ROOT}/scripts/manage.sh" "\${dest}"
        ;;
    */scripts/sentinel-firmware-update)
        cp "${REPO_ROOT}/scripts/sentinel-firmware-update" "\${dest}"
        ;;
    */scripts/sentinel-firmware-update-dispatch)
        cp "${REPO_ROOT}/scripts/sentinel-firmware-update-dispatch" "\${dest}"
        ;;
    */systemd/sentinel-firmware-update-dispatch.service.in)
        cp "${REPO_ROOT}/systemd/sentinel-firmware-update-dispatch.service.in" "\${dest}"
        ;;
    */systemd/sentinel-firmware-update-dispatch.path.in)
        cp "${REPO_ROOT}/systemd/sentinel-firmware-update-dispatch.path.in" "\${dest}"
        ;;
    *)
        echo "unexpected curl url: \${url}" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

cat > "${FAKE_BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${TEST_SYSTEMCTL_LOG}"
EOF
chmod +x "${FAKE_BIN_DIR}/systemctl"

cat > "${FAKE_BIN_DIR}/id" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-u" ]]; then
    echo 0
    exit 0
fi

if [[ "${1:-}" == "sentinel" ]]; then
    exit 0
fi

exit 0
EOF
chmod +x "${FAKE_BIN_DIR}/id"

cat > "${FAKE_BIN_DIR}/chown" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
chmod +x "${FAKE_BIN_DIR}/chown"

cat > "${FAKE_BIN_DIR}/chmod" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

mode="$1"
shift

if [[ "${mode}" == "2775" ]]; then
    exec /bin/chmod 775 "$@"
fi

exec /bin/chmod "${mode}" "$@"
EOF
chmod +x "${FAKE_BIN_DIR}/chmod"

export TEST_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"

cp "${INSTALLER}" "${TMP_DIR}/install-firmware-updater.sh"
PATH="${FAKE_BIN_DIR}:$PATH" \
    INSTALL_BIN_DIR="${INSTALL_BIN_DIR}" \
    SYSTEMD_DIR="${SYSTEMD_DIR}" \
    STATE_DIR="${INSTALL_STATE_DIR}" \
    sh "${TMP_DIR}/install-firmware-updater.sh"

[[ -x "${INSTALL_BIN_DIR}/sentinel-manage" ]] || fail "installer should install sentinel-manage"
[[ -x "${INSTALL_BIN_DIR}/sentinel-firmware-update" ]] || fail "installer should install wrapper"
[[ -x "${INSTALL_BIN_DIR}/sentinel-firmware-update-dispatch" ]] || fail "installer should install dispatcher"
[[ -f "${SYSTEMD_DIR}/sentinel-firmware-update-dispatch.service" ]] || fail "installer should install service unit"
[[ -f "${SYSTEMD_DIR}/sentinel-firmware-update-dispatch.path" ]] || fail "installer should install path unit"
[[ -d "${INSTALL_STATE_DIR}/requests" ]] || fail "installer should create request directory"
[[ -d "${INSTALL_STATE_DIR}/results" ]] || fail "installer should create result directory"

assert_contains "$(cat "${SYSTEMD_DIR}/sentinel-firmware-update-dispatch.service")" "ExecStart=${INSTALL_BIN_DIR}/sentinel-firmware-update-dispatch" "service unit render"
assert_contains "$(cat "${SYSTEMD_DIR}/sentinel-firmware-update-dispatch.path")" "PathExistsGlob=${INSTALL_STATE_DIR}/requests/*.req" "path unit render"
assert_contains "$(cat "${SYSTEMCTL_LOG}")" "daemon-reload" "systemctl daemon-reload"
assert_contains "$(cat "${SYSTEMCTL_LOG}")" "enable --now sentinel-firmware-update-dispatch.path" "path unit enable"

echo "Firmware updater checks passed."
