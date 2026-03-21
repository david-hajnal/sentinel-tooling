#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="${REPO_ROOT}/scripts/sentinel-firmware-update"

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

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

STUB_BIN_DIR="${TMP_DIR}/bin"
MANAGE_LOG="${TMP_DIR}/manage.log"
VERSION_FILE="${TMP_DIR}/etc/sentinel_rtp_cam/firmware-version"
mkdir -p "$STUB_BIN_DIR"

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

if [[ -n "${target_version}" && "${target_version}" != "latest" ]]; then
    mkdir -p "$(dirname "${TEST_FIRMWARE_VERSION_FILE}")"
    printf '%s\n' "${target_version}" > "${TEST_FIRMWARE_VERSION_FILE}"
fi
EOF
chmod +x "${STUB_BIN_DIR}/sentinel-manage"

export PATH="${STUB_BIN_DIR}:$PATH"
export TEST_SENTINEL_MANAGE_LOG="${MANAGE_LOG}"
export TEST_FIRMWARE_VERSION_FILE="${VERSION_FILE}"

"${WRAPPER}" 1.1.3
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update 1.1.3" "version mapping"
assert_file_eq "${VERSION_FILE}" "1.1.3" "firmware version file write"

"${WRAPPER}" 1.1.3 --start
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update 1.1.3 --start" "version mapping with start"

"${WRAPPER}" latest
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update latest" "latest mapping"

"${WRAPPER}" v1.1.3
assert_eq "$(tr -d '\n' < "${MANAGE_LOG}")" "update 1.1.3" "v-prefixed version normalization"

ROLLBACK_OUTPUT="${TMP_DIR}/rollback.out"
if "${WRAPPER}" --rollback >"${ROLLBACK_OUTPUT}" 2>&1; then
    fail "rollback should fail"
fi

if ! grep -q "Rollback is not supported" "${ROLLBACK_OUTPUT}"; then
    fail "rollback error message should explain the limitation"
fi

echo "Firmware updater wrapper checks passed."
