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

MANAGE_LIB="${TMP_DIR}/manage-lib.sh"
sed '/^# Main command dispatcher/,$d' "${MANAGE}" > "${MANAGE_LIB}"
# shellcheck disable=SC1090
source "${MANAGE_LIB}"

RELEASE_DIR="${TMP_DIR}/release"
mkdir -p "${RELEASE_DIR}/payload"
printf '#!/usr/bin/env bash\nexit 0\n' > "${RELEASE_DIR}/payload/agent_forward"
chmod 755 "${RELEASE_DIR}/payload/agent_forward"
(
    cd "${RELEASE_DIR}/payload"
    tar -czf "${RELEASE_DIR}/agent_forward-2.0.3-aarch64.tar.gz" agent_forward
)
(
    cd "${RELEASE_DIR}"
    sha256sum agent_forward-2.0.3-aarch64.tar.gz > agent_forward-2.0.3-aarch64.tar.gz.sha256
)

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
        -f|-s|-S|-L|-fsSL|--progress-bar|--max-time)
            shift
            if [[ "\${1:-}" != "" && ("\$0" == *curl || "\$1" =~ ^[0-9]+$) ]]; then
                if [[ "\$1" =~ ^[0-9]+$ ]]; then
                    shift
                fi
            fi
            ;;
        *)
            url="\$1"
            shift
            ;;
    esac
done

case "\${url}" in
    */sentinel-agent-2.0.3-aarch64.tar.gz|*/sentinel-agent-2.0.3-aarch64.tar.gz.sha256)
        exit 22
        ;;
    */agent_forward-2.0.3-aarch64.tar.gz)
        cp "${RELEASE_DIR}/agent_forward-2.0.3-aarch64.tar.gz" "\${dest}"
        ;;
    */agent_forward-2.0.3-aarch64.tar.gz.sha256)
        cat "${RELEASE_DIR}/agent_forward-2.0.3-aarch64.tar.gz.sha256"
        ;;
    *)
        echo "unexpected curl url: \${url}" >&2
        exit 1
        ;;
esac
EOF
chmod +x "${FAKE_BIN_DIR}/curl"

export PATH="${FAKE_BIN_DIR}:$PATH"
UPDATE_REPO="david-hajnal/sentinel-video-receiver"
UPDATE_BASE_URL="https://github.com/${UPDATE_REPO}/releases/download"
UPDATE_BINARY_NAME="sentinel-agent"

OUTPUT_PATH="${TMP_DIR}/sentinel-agent"
LOG_FILE="${TMP_DIR}/download.log"
if ! update_download_and_verify "aarch64" "2.0.3" "${OUTPUT_PATH}" >"${LOG_FILE}" 2>&1; then
    cat "${LOG_FILE}" >&2
    fail "download helper should fall back to legacy release asset names"
fi

[[ -x "${OUTPUT_PATH}" ]] || fail "download helper should write installed binary"
LOG_OUTPUT="$(cat "${LOG_FILE}")"
assert_contains "${LOG_OUTPUT}" "sentinel-agent-2.0.3-aarch64.tar.gz" "download should try current asset name first"
assert_contains "${LOG_OUTPUT}" "agent_forward-2.0.3-aarch64.tar.gz" "download should fall back to legacy asset name"

echo "Manage download compatibility checks passed."
