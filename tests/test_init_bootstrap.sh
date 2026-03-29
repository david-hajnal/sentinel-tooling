#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INIT_SCRIPT="${REPO_ROOT}/init.sh"

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
INSTALL_DIR="${TMP_DIR}/install-bin"
LOG_FILE="${TMP_DIR}/bootstrap.log"
MANAGE_CALLS="${TMP_DIR}/manage-calls.log"
mkdir -p "${FAKE_BIN_DIR}" "${INSTALL_DIR}"

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
        cat > "\${dest}" <<'MANAGE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >> "${MANAGE_CALLS}"
MANAGE
        ;;
    */scripts/install-firmware-updater.sh)
        cat > "\${dest}" <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail
printf 'firmware-installer\n' >> "${MANAGE_CALLS}"
INSTALLER
        ;;
    *)
        echo "unexpected curl url: \${url}" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

export PATH="${FAKE_BIN_DIR}:$PATH"
export MANAGE_CALLS
export SENTINEL_MANAGE_INSTALL_DIR="${INSTALL_DIR}"

bash "${INIT_SCRIPT}" >"${LOG_FILE}" 2>&1

[[ -x "${INSTALL_DIR}/sentinel-manage" ]] || fail "bootstrap should install sentinel-manage"

CALLS="$(cat "${MANAGE_CALLS}")"
assert_contains "${CALLS}" "update latest" "bootstrap should install sentinel-agent"
assert_contains "${CALLS}" "firmware-installer" "bootstrap should install firmware updater support"
assert_contains "$(cat "${LOG_FILE}")" "Bootstrap install complete. Next step: sudo sentinel-manage init" "bootstrap completion message"

echo "Bootstrap init checks passed."
