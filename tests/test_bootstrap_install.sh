#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP="${REPO_ROOT}/init.sh"

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
INSTALL_DIR="${TMP_DIR}/install"
LOG_FILE="${TMP_DIR}/manage.log"
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
        cat > "\${dest}" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >> "${LOG_FILE}"
SCRIPT
        ;;
    *)
        echo "unexpected curl url: \${url}" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

PATH="${FAKE_BIN_DIR}:$PATH" \
LOG_FILE="${LOG_FILE}" \
SENTINEL_MANAGE_INSTALL_DIR="${INSTALL_DIR}" \
bash "${BOOTSTRAP}"

[[ -x "${INSTALL_DIR}/sentinel-manage" ]] || fail "bootstrap should install sentinel-manage"

RUN_LOG="$(cat "${LOG_FILE}")"
assert_contains "${RUN_LOG}" "update latest" "bootstrap should install sentinel-agent before init"
assert_contains "${RUN_LOG}" "init" "bootstrap should run init after update"

FIRST_LINE="$(sed -n '1p' "${LOG_FILE}")"
SECOND_LINE="$(sed -n '2p' "${LOG_FILE}")"
[[ "${FIRST_LINE}" == "update latest" ]] || fail "bootstrap should run update latest first"
[[ "${SECOND_LINE}" == "init" ]] || fail "bootstrap should run init second"

echo "Bootstrap install checks passed."
