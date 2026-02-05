#!/bin/bash
# Sentinel RTP Camera - Management Script
# Quick access to common management commands

set -e

SERVICE_NAME_LEGACY="sentinel_rtp_cam"
SERVICE_NAME_FORWARD="sentinel_rtp_cam_forward"
CONFIG_DIR="/etc/sentinel_rtp_cam"
SERVER_CONFIG_JSON="${CONFIG_DIR}/server.json"
CAMERA_CONFIG_JSON="${CONFIG_DIR}/camera.json"
CLIPS_DIR="/var/lib/sentinel_rtp_cam/clips"
FORWARD_BIN="/usr/local/bin/${SERVICE_NAME_FORWARD}"
FORWARD_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME_FORWARD}.service"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  config       Edit camera configuration (default)"
    echo "  config server Edit server configuration"
    echo "  config camera Edit camera configuration"
    echo "  init         Initialize agent (server setup + registration token)"
    echo "  clips        List clips in storage directory"
    echo "  restart      Restart the service"
    echo "  stop         Stop the service"
    echo "  start        Start the service (defaults to forward mode)"
    echo "  status       Show service status"
    echo "  logs         Follow live logs"
    echo "  logs-recent  Show recent logs (last 50 lines)"
    echo "  clean        Delete all clips (with confirmation)"
    echo "  update       Download and install updated binaries"
    echo ""
    echo "Examples:"
    echo "  $0 config camera"
    echo "  $0 config server"
    echo "  $0 init"
    echo "  $0 restart"
    echo "  $0 start forward"
    echo "  $0 start legacy"
    echo "  $0 logs"
    echo "  $0 update latest"
    echo "  $0 update v0.6.2 --dry-run"
    echo ""
    echo "Mode selection:"
    echo "  - If no mode is passed, the script defaults to forward mode."
    echo "  - Set forward_agent.mode in $CAMERA_CONFIG_JSON to pin the mode."
    echo "  - If forward service is missing but ${FORWARD_BIN} exists, the script will create it."
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}This command requires sudo. Re-running with sudo...${NC}"
        exec sudo "$0" "$@"
    fi
}

systemd_service_exists() {
    local service="$1"
    systemctl cat "${service}.service" >/dev/null 2>&1
}

forward_binary_exists() {
    [[ -x "$FORWARD_BIN" ]]
}

ensure_forward_service() {
    if systemd_service_exists "$SERVICE_NAME_FORWARD"; then
        return 0
    fi
    if ! forward_binary_exists; then
        return 1
    fi

    echo -e "${YELLOW}Forward service not installed; creating ${SERVICE_NAME_FORWARD}.service${NC}"
    cat > "$FORWARD_SERVICE_FILE" <<EOF
[Unit]
Description=Sentinel RTP Camera Agent (forward)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel
Group=sentinel
WorkingDirectory=/var/lib/sentinel_rtp_cam

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sentinel_rtp_cam
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true

# Resource limits
LimitNOFILE=65536

# Environment
Environment=SERVER_CONFIG_JSON=/etc/sentinel_rtp_cam/server.json
Environment=CAMERA_CONFIG_JSON=/etc/sentinel_rtp_cam/camera.json
EnvironmentFile=/etc/sentinel_rtp_cam/env

# Execution
ExecStart=$FORWARD_BIN

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME_FORWARD

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$FORWARD_SERVICE_FILE"
    systemctl daemon-reload
    return 0
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_dry() {
    echo -e "${BLUE}[DRY-RUN]${NC} $*"
}

die() {
    log_error "$*"
    exit 1
}

json_get_file() {
    local file="$1"
    local key="$2"
    if [[ -z "$file" || ! -f "$file" ]]; then
        return
    fi
    python3 - "$file" "$key" <<'PY'
import json
import sys

path = sys.argv[1]
key = sys.argv[2]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    sys.exit(0)

cur = data
for part in key.split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        sys.exit(0)

if cur is None:
    sys.exit(0)
if isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, (int, float, str)):
    print(cur)
PY
}

json_get() {
    local key="$1"
    json_get_file "$CAMERA_CONFIG_JSON" "$key"
}

resolve_mode() {
    local mode="${1:-}"
    if [[ -z "$mode" && -f "$CAMERA_CONFIG_JSON" ]]; then
        mode=$(json_get "forward_agent.mode")
        case "$mode" in
            forward|legacy) ;;
            *) mode="" ;;
        esac
        if [[ -z "$mode" ]]; then
            if [[ -n "$(json_get "forward_agent.server_addr")" ]]; then
                mode="forward"
            fi
        fi
    fi
    if [[ -z "$mode" ]]; then
        mode="forward"
    fi
    echo "$mode"
}

resolve_service() {
    local mode
    mode=$(resolve_mode "${1:-}")

    if [[ "$mode" == "forward" ]]; then
        ACTIVE_SERVICE="$SERVICE_NAME_FORWARD"
        ACTIVE_MODE="forward"
        if ! systemd_service_exists "$ACTIVE_SERVICE"; then
            ensure_forward_service || true
        fi
        if ! systemd_service_exists "$ACTIVE_SERVICE"; then
            echo -e "${YELLOW}Forward service not installed; falling back to legacy (${SERVICE_NAME_LEGACY})${NC}"
            ACTIVE_SERVICE="$SERVICE_NAME_LEGACY"
            ACTIVE_MODE="legacy"
        fi
    else
        ACTIVE_SERVICE="$SERVICE_NAME_LEGACY"
        ACTIVE_MODE="legacy"
        if ! systemd_service_exists "$ACTIVE_SERVICE" && systemd_service_exists "$SERVICE_NAME_FORWARD"; then
            echo -e "${YELLOW}Legacy service not installed; using forward (${SERVICE_NAME_FORWARD})${NC}"
            ACTIVE_SERVICE="$SERVICE_NAME_FORWARD"
            ACTIVE_MODE="forward"
        fi
    fi
}

cmd_config() {
    check_root
    local target="${2:-camera}"
    case "$target" in
        camera|"")
            ensure_camera_json
            nano "$CAMERA_CONFIG_JSON"
            ;;
        server)
            ensure_server_json
            nano "$SERVER_CONFIG_JSON"
            ;;
        *)
            log_error "Unknown config target: $target"
            show_usage
            exit 1
            ;;
    esac
}

cmd_clips() {
    check_root
    echo -e "${GREEN}Clips in $CLIPS_DIR:${NC}"
    ls -lh "$CLIPS_DIR" || echo "No clips found or directory empty"
    echo ""
    echo -e "${BLUE}Disk usage:${NC}"
    du -sh "$CLIPS_DIR" 2>/dev/null || echo "N/A"
    df -h "$CLIPS_DIR"
}

cmd_restart() {
    check_root
    resolve_service "${2:-}"
    echo -e "${YELLOW}Restarting $ACTIVE_SERVICE ($ACTIVE_MODE)...${NC}"
    systemctl restart "$ACTIVE_SERVICE"
    sleep 2
    systemctl status "$ACTIVE_SERVICE" --no-pager
}

cmd_stop() {
    check_root
    resolve_service "${2:-}"
    echo -e "${YELLOW}Stopping $ACTIVE_SERVICE ($ACTIVE_MODE)...${NC}"
    systemctl stop "$ACTIVE_SERVICE"
    systemctl status "$ACTIVE_SERVICE" --no-pager
}

cmd_start() {
    check_root
    resolve_service "${2:-}"
    echo -e "${GREEN}Starting $ACTIVE_SERVICE ($ACTIVE_MODE)...${NC}"
    systemctl start "$ACTIVE_SERVICE"
    sleep 2
    systemctl status "$ACTIVE_SERVICE" --no-pager
}

cmd_status() {
    check_root
    resolve_service "${2:-}"
    systemctl status "$ACTIVE_SERVICE" --no-pager
}

cmd_logs() {
    check_root
    resolve_service "${2:-}"
    echo -e "${GREEN}Following logs for $ACTIVE_SERVICE ($ACTIVE_MODE) (Ctrl+C to exit)...${NC}"
    journalctl -u "$ACTIVE_SERVICE" -f
}

cmd_logs_recent() {
    check_root
    resolve_service "${2:-}"
    echo -e "${GREEN}Recent logs for $ACTIVE_SERVICE ($ACTIVE_MODE):${NC}"
    journalctl -u "$ACTIVE_SERVICE" -n 50 --no-pager
}

cmd_clean() {
    check_root
    echo -e "${RED}WARNING: This will delete ALL clips in $CLIPS_DIR${NC}"
    read -p "Are you sure? Type 'yes' to confirm: " confirm
    if [[ "$confirm" == "yes" ]]; then
        echo -e "${YELLOW}Deleting all clips...${NC}"
        rm -f "$CLIPS_DIR"/*.mp4 "$CLIPS_DIR"/*.mp4.part
        echo -e "${GREEN}Done. Clips deleted.${NC}"
    else
        echo "Cancelled."
    fi
}

ensure_server_json() {
    if [[ -f "$SERVER_CONFIG_JSON" ]]; then
        return
    fi

    log_warn "Server config JSON not found, creating: $SERVER_CONFIG_JSON"
    mkdir -p "$CONFIG_DIR"
    cat > "$SERVER_CONFIG_JSON" <<'EOF'
{
  "server": {
    "enabled": null,
    "base_url": null,
    "bearer_token": null,
    "retry_interval_secs": null,
    "max_retries": null
  }
}
EOF
    chmod 600 "$SERVER_CONFIG_JSON"
}

ensure_camera_json() {
    if [[ -f "$CAMERA_CONFIG_JSON" ]]; then
        return
    fi

    log_warn "Camera config JSON not found, creating: $CAMERA_CONFIG_JSON"
    mkdir -p "$CONFIG_DIR"
    cat > "$CAMERA_CONFIG_JSON" <<'EOF'
{
  "cameras": [
    {
      "id": null,
      "user": null,
      "pass": null,
      "transport": null,
      "motion": {
        "enabled": null
      },
      "features": {
        "local_clip_enabled": null,
        "rtsp_receiver_enabled": null
      },
      "rtsp": {
        "url": null,
        "stream_id": null
      },
      "onvif": {
        "url": null,
        "debug": null,
        "dump_xml": null,
        "sub_termination": null,
        "renew_every_secs": null,
        "pull_timeout": null,
        "pull_limit": null,
        "resubscribe_after_errors": null,
        "min_poll_gap_ms": null,
        "after_sub_delay_ms": null,
        "connrefused_retries": null,
        "connrefused_backoff_ms": null
      }
    }
  ],
  "cleanup": {
    "interval_secs": null,
    "min_free_bytes": null
  },
  "ingest": {
    "clip_dir": null,
    "clip_pre_secs": null,
    "clip_post_secs": null,
    "clip_ring_secs": null,
    "clip_stale_part_secs": null,
    "clip_max_secs": null
  },
  "forward_agent": {
    "mode": null,
    "server_addr": null,
    "motion_merge_secs": null
  },
  "logging": {
    "rust_log": null
  },
  "version": {
    "sentinel_version": null
  }
}
EOF
    chmod 600 "$CAMERA_CONFIG_JSON"
}

update_server_json() {
    local base_url="$1"
    local bearer_token="$2"

    python3 - "$SERVER_CONFIG_JSON" "$base_url" "$bearer_token" <<'PY'
import json
import sys

path = sys.argv[1]
base_url = sys.argv[2].strip()
bearer = sys.argv[3].strip()

try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    data = {}

if not isinstance(data, dict):
    data = {}

server = data.get("server")
if not isinstance(server, dict):
    server = {}

if base_url:
    server["base_url"] = base_url.rstrip("/")
if bearer:
    server["bearer_token"] = bearer
if base_url or bearer:
    server["enabled"] = True

data["server"] = server

with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
PY
    chmod 600 "$SERVER_CONFIG_JSON"
}

pull_remote_config() {
    local base_url="$1"
    local bearer_token="$2"
    local camera_hint="${3:-}"

    if [[ -z "$base_url" || -z "$bearer_token" ]]; then
        log_warn "Missing server base URL or bearer token; skipping config pull."
        return 0
    fi

    local url="${base_url%/}/api/v1/config"
    local tmp
    tmp=$(mktemp)
    local header_args=(-H "Authorization: Bearer ${bearer_token}")
    if [[ -n "$camera_hint" ]]; then
        header_args+=(-H "x-camera-id: ${camera_hint}")
    fi

    if ! curl -fsS "${header_args[@]}" "$url" -o "$tmp"; then
        rm -f "$tmp"
        log_warn "No config pulled from server (missing or unauthorized)."
        return 0
    fi

    if ! python3 - "$SERVER_CONFIG_JSON" "$CAMERA_CONFIG_JSON" < "$tmp" <<'PY'
import json
import sys

server_path = sys.argv[1]
camera_path = sys.argv[2]

try:
    payload = json.load(sys.stdin)
except Exception:
    sys.stderr.write("Invalid JSON payload\n")
    sys.exit(1)

config = payload.get("config")
if not isinstance(config, dict):
    sys.stderr.write("Missing config payload\n")
    sys.exit(1)

def load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

def merge(base, update):
    if isinstance(base, dict) and isinstance(update, dict):
        for key, value in update.items():
            if key in base:
                base[key] = merge(base[key], value)
            else:
                base[key] = value
        return base
    return update

server_update = config.get("server") if isinstance(config.get("server"), dict) else None
if server_update is not None:
    server_value = load(server_path)
    if not isinstance(server_value.get("server"), dict):
        server_value["server"] = {}
    server_value["server"] = merge(server_value["server"], server_update)
    with open(server_path, "w", encoding="utf-8") as fh:
        json.dump(server_value, fh, indent=2)

camera_update = dict(config)
camera_update.pop("server", None)
camera_value = load(camera_path)
camera_value = merge(camera_value, camera_update)
with open(camera_path, "w", encoding="utf-8") as fh:
    json.dump(camera_value, fh, indent=2)
PY
    then
        rm -f "$tmp"
        log_warn "Failed to parse config payload from server."
        return 0
    fi

    rm -f "$tmp"
    chmod 600 "$SERVER_CONFIG_JSON" "$CAMERA_CONFIG_JSON"
    log_info "Pulled camera config from server."
}

cmd_init() {
    check_root

    ensure_server_json
    ensure_camera_json

    local machine_id=""
    if [[ -f /etc/machine-id ]]; then
        machine_id=$(cat /etc/machine-id)
    fi
    if [[ -z "$machine_id" ]]; then
        machine_id=$(uuidgen 2>/dev/null || openssl rand -hex 16)
    fi

    local default_user
    default_user=$(whoami)
    local default_agent
    default_agent=$(hostname)

    local username=""
    local agent_name=""
    read -p "Username [${default_user}]: " username
    username="${username:-$default_user}"
    read -p "Agent name [${default_agent}]: " agent_name
    agent_name="${agent_name:-$default_agent}"

    local issued_at
    issued_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local jwt_secret="${SENTINEL_INIT_JWT_SECRET:-}"
    local jwt_token
    jwt_token=$(python3 - "$jwt_secret" "$machine_id" "$agent_name" "$username" "$issued_at" <<'PY'
import base64
import hashlib
import hmac
import json
import sys

secret, machine_id, agent_name, username, issued_at = sys.argv[1:6]

def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("utf-8")

header = {"alg": "HS256", "typ": "JWT"} if secret else {"alg": "none", "typ": "JWT"}
payload = {
    "machine_id": machine_id,
    "agent_name": agent_name,
    "username": username,
    "issued_at": issued_at,
}

segments = [
    b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
    b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
]

if secret:
    signing_input = ".".join(segments).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    segments.append(b64url(signature))

print(".".join(segments))
PY
    )

    local init_file="${CONFIG_DIR}/agent-init.json"
    cat > "$init_file" <<EOF
{
  "machine_id": "${machine_id}",
  "username": "${username}",
  "agent_name": "${agent_name}",
  "issued_at": "${issued_at}",
  "jwt": "${jwt_token}"
}
EOF
    chmod 600 "$init_file"

    log_info "Registration token generated."
    log_info "Machine ID: ${machine_id}"
    log_info "Agent name: ${agent_name}"
    log_info "Username: ${username}"
    log_info "JWT saved to: ${init_file}"
    if [[ -z "$jwt_secret" ]]; then
        log_warn "SENTINEL_INIT_JWT_SECRET not set; generated unsigned JWT."
    fi

    local existing_base_url
    existing_base_url=$(json_get_file "$SERVER_CONFIG_JSON" "server.base_url")
    local default_base_url="${existing_base_url:-${SENTINEL_SERVER_BASE_URL:-}}"
    local server_base_url=""
    if [[ -n "$default_base_url" ]]; then
        read -p "Server base URL [${default_base_url}]: " server_base_url
        server_base_url="${server_base_url:-$default_base_url}"
    else
        read -p "Server base URL: " server_base_url
    fi

    local existing_token
    existing_token=$(json_get_file "$SERVER_CONFIG_JSON" "server.bearer_token")
    local bearer_token=""
    if [[ -n "$existing_token" ]]; then
        read -s -p "Bearer token (leave blank to keep existing): " bearer_token
        echo ""
        bearer_token="${bearer_token:-$existing_token}"
    else
        read -s -p "Bearer token: " bearer_token
        echo ""
    fi

    if [[ -n "$server_base_url" || -n "$bearer_token" ]]; then
        update_server_json "$server_base_url" "$bearer_token"
        log_info "Server config updated: ${SERVER_CONFIG_JSON}"
    else
        log_warn "Server base URL or bearer token not set; server.json unchanged."
    fi

    pull_remote_config "$server_base_url" "$bearer_token"

    cmd_start
}

update_detect_arch() {
    local machine
    machine=$(uname -m)
    case "$machine" in
        armv7l) echo "armv7" ;;
        aarch64) echo "aarch64" ;;
        *) die "Unsupported architecture: $machine" ;;
    esac
}

update_get_installed_version() {
    echo 1
}

update_download_and_verify() {
    local arch="$1"
    local version="$2"
    local output_path="$3"
    local output_forward_path="$4"

    version="${version#v}"

    if [[ "$version" == "latest" ]]; then
        log_info "Fetching latest release version from GitHub API..."
        version=$(curl -fsSL --max-time 30 "https://api.github.com/repos/${UPDATE_REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        if [[ -z "$version" ]]; then
            log_error "Failed to fetch latest version from GitHub API"
            log_error "Check releases manually: https://github.com/${UPDATE_REPO}/releases"
            return 1
        fi
        log_info "✓ Latest version resolved: v$version"
    else
        log_info "Using specified version: v$version"
    fi

    local tarball_name="${UPDATE_BINARY_NAME}-${version}-${arch}.tar.gz"
    local download_url="${UPDATE_BASE_URL}/v${version}/${tarball_name}"
    local checksum_url="${UPDATE_BASE_URL}/v${version}/${tarball_name}.sha256"
    local temp_dir
    temp_dir=$(mktemp -d)
    local tarball_path="${temp_dir}/${tarball_name}"

    log_info "Downloading ${tarball_name}..."
    log_info "From: $download_url"
    log_info "To: $tarball_path"

    if ! curl -fL --progress-bar --max-time 300 -o "$tarball_path" "$download_url"; then
        log_error "Download failed!"
        rm -rf "$temp_dir"
        return 1
    fi

    log_info "✓ Download completed: $(du -h "$tarball_path" | cut -f1)"

    log_info "Verifying SHA256 checksum..."
    local expected_sha
    expected_sha=$(curl -fsSL --max-time 30 "$checksum_url" | awk '{print $1}')
    if [[ -z "$expected_sha" ]]; then
        log_warn "Could not fetch checksum file, skipping verification"
    else
        local actual_sha
        actual_sha=$(sha256sum "$tarball_path" | awk '{print $1}')
        if [[ "$expected_sha" != "$actual_sha" ]]; then
            log_error "Checksum verification FAILED!"
            rm -rf "$temp_dir"
            return 1
        fi
        log_info "✓ Checksum verified successfully"
    fi

    log_info "Extracting tarball..."
    if ! tar -xzf "$tarball_path" -C "$temp_dir"; then
        log_error "Failed to extract tarball"
        rm -rf "$temp_dir"
        return 1
    fi

    if [[ ! -f "${temp_dir}/${UPDATE_BINARY_NAME}" ]]; then
        log_error "Binary '${UPDATE_BINARY_NAME}' not found in tarball!"
        rm -rf "$temp_dir"
        return 1
    fi

    mv "${temp_dir}/${UPDATE_BINARY_NAME}" "$output_path"
    chmod 755 "$output_path"

    if [[ -f "${temp_dir}/${UPDATE_FORWARD_BINARY_NAME}" ]]; then
        mv "${temp_dir}/${UPDATE_FORWARD_BINARY_NAME}" "$output_forward_path"
        chmod 755 "$output_forward_path"
    else
        log_warn "Forward binary '${UPDATE_FORWARD_BINARY_NAME}' not found in tarball; skipping"
    fi

    rm -rf "$temp_dir"
    return 0
}

update_create_backup_binary() {
    local binary_name="$1"
    local current="${UPDATE_INSTALL_DIR}/${binary_name}"
    local backup="${UPDATE_INSTALL_DIR}/${binary_name}.prev"

    if [[ ! -f "$current" ]]; then
        log_warn "No current binary to back up (fresh install)"
        return
    fi

    if [[ $UPDATE_DRY_RUN -eq 1 ]]; then
        log_dry "Would back up: $current -> $backup"
        return
    fi

    if ! cp -f "$current" "$backup"; then
        log_error "Failed to create backup!"
        return 1
    fi
}

update_install_new_binary_to() {
    local new_binary="$1"
    local target="$2"

    if [[ $UPDATE_DRY_RUN -eq 1 ]]; then
        log_dry "Would install: $new_binary -> $target"
        return
    fi

    if ! mv -f "$new_binary" "$target"; then
        log_error "Failed to move binary to install location!"
        return 1
    fi

    chmod 755 "$target"
}

update_restart_service() {
    if [[ $UPDATE_DRY_RUN -eq 1 ]]; then
        log_dry "Would restart service: $UPDATE_SERVICE_NAME"
        return
    fi

    systemctl stop "$UPDATE_SERVICE_NAME" || true
    if ! systemctl start "$UPDATE_SERVICE_NAME"; then
        log_error "Failed to start service"
        journalctl -u "$UPDATE_SERVICE_NAME" -n 20 --no-pager
        return 1
    fi

    if systemctl list-unit-files --type=service | grep -q "^${UPDATE_FORWARD_SERVICE_NAME}\\.service"; then
        if ! systemctl restart "$UPDATE_FORWARD_SERVICE_NAME"; then
            log_warn "Failed to restart $UPDATE_FORWARD_SERVICE_NAME"
        fi
    fi
}

update_ensure_config_json() {
    ensure_server_json
    ensure_camera_json
}

update_install_manage_script() {
    local manage_src
    manage_src="$(cd "$(dirname "$0")" && pwd)/manage.sh"
    local manage_dst="/usr/local/bin/sentinel-manage"
    if [[ ! -f "$manage_src" ]]; then
        log_warn "manage.sh not found at $manage_src; skipping install"
        return
    fi
    cp -f "$manage_src" "$manage_dst"
    chmod 755 "$manage_dst"
}

cmd_update() {
    check_root

    UPDATE_BINARY_NAME="sentinel_rtp_cam"
    UPDATE_FORWARD_BINARY_NAME="sentinel_rtp_cam_forward"
    UPDATE_INSTALL_DIR="/usr/local/bin"
    UPDATE_CONFIG_DIR="/etc/${UPDATE_BINARY_NAME}"
    UPDATE_SERVER_JSON="${UPDATE_CONFIG_DIR}/server.json"
    UPDATE_CAMERA_JSON="${UPDATE_CONFIG_DIR}/camera.json"
    UPDATE_SERVICE_NAME="${UPDATE_BINARY_NAME}"
    UPDATE_FORWARD_SERVICE_NAME="${UPDATE_FORWARD_BINARY_NAME}"
    UPDATE_REPO="${SENTINEL_REPO:-david-hajnal/sentinel-video-receiver}"
    UPDATE_BASE_URL="${SENTINEL_BASE_URL:-https://github.com/${UPDATE_REPO}/releases/download}"
    UPDATE_VERSION="${SENTINEL_VERSION:-latest}"
    UPDATE_DRY_RUN=0

    local args=("$@")
    local idx=0
    while [[ $idx -lt ${#args[@]} ]]; do
        case "${args[$idx]}" in
            --dry-run)
                UPDATE_DRY_RUN=1
                ;;
            -*)
                die "Unknown option: ${args[$idx]}"
                ;;
            *)
                UPDATE_VERSION="${args[$idx]}"
                ;;
        esac
        idx=$((idx + 1))
    done

    log_info "Starting sentinel_rtp_cam update..."
    log_info "Target version: $UPDATE_VERSION"
    log_info "Server config JSON: $UPDATE_SERVER_JSON"
    log_info "Camera config JSON: $UPDATE_CAMERA_JSON"

    update_ensure_config_json
    update_install_manage_script

    if [[ ! -f "${UPDATE_INSTALL_DIR}/${UPDATE_BINARY_NAME}" ]]; then
        die "Service not installed. Install the binary + systemd unit first."
    fi

    local current_version
    current_version=$(update_get_installed_version)
    log_info "Current version: $current_version"

    if [[ "$current_version" == "$UPDATE_VERSION" && "$UPDATE_VERSION" != "latest" ]]; then
        log_info "Already running target version $UPDATE_VERSION"
        exit 0
    fi

    local arch
    arch=$(update_detect_arch)
    log_info "Architecture: $arch"

    local new_binary="${UPDATE_INSTALL_DIR}/${UPDATE_BINARY_NAME}.new"
    local new_forward_binary="${UPDATE_INSTALL_DIR}/${UPDATE_FORWARD_BINARY_NAME}.new"

    if [[ $UPDATE_DRY_RUN -eq 1 ]]; then
        log_dry "Would download version $UPDATE_VERSION for $arch"
        log_dry "Would install to: $new_binary"
        log_dry "Would install to: $new_forward_binary"
        return
    fi

    if ! update_download_and_verify "$arch" "$UPDATE_VERSION" "$new_binary" "$new_forward_binary"; then
        die "Failed to download and verify new binary"
    fi

    update_create_backup_binary "$UPDATE_BINARY_NAME"
    if [[ -f "${UPDATE_INSTALL_DIR}/${UPDATE_FORWARD_BINARY_NAME}" ]]; then
        update_create_backup_binary "$UPDATE_FORWARD_BINARY_NAME"
    fi

    update_install_new_binary_to "$new_binary" "${UPDATE_INSTALL_DIR}/${UPDATE_BINARY_NAME}"
    if [[ -f "$new_forward_binary" ]]; then
        update_install_new_binary_to "$new_forward_binary" "${UPDATE_INSTALL_DIR}/${UPDATE_FORWARD_BINARY_NAME}"
    fi

    update_restart_service
}

# Main command dispatcher
case "${1:-}" in
    config)
        cmd_config "$@"
        ;;
    clips|ls)
        cmd_clips
        ;;
    restart)
        cmd_restart "$@"
        ;;
    stop)
        cmd_stop "$@"
        ;;
    start)
        cmd_start "$@"
        ;;
    status)
        cmd_status "$@"
        ;;
    logs)
        cmd_logs "$@"
        ;;
    logs-recent|recent)
        cmd_logs_recent "$@"
        ;;
    clean)
        cmd_clean
        ;;
    init)
        cmd_init
        ;;
    update)
        shift
        cmd_update "$@"
        ;;
    help|--help|-h|"")
        show_usage
        exit 0
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac
