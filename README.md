# sentinel-tooling

## Installation

### 1. Bootstrap the device

This installs `/usr/local/bin/sentinel-manage`, the latest `sentinel-agent` binary, and managed firmware updater support.

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/init.sh -o /tmp/sentinel-init.sh
sudo bash /tmp/sentinel-init.sh
```

If you want the bootstrap to start the service immediately after install:

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/init.sh -o /tmp/sentinel-init.sh
chmod +x /tmp/sentinel-init.sh
sudo SENTINEL_START_AFTER_INSTALL=1 /tmp/sentinel-init.sh
```

### 2. Register the agent

```bash
sudo sentinel-manage init
```

### 3. Start the service

```bash
sudo sentinel-manage start
```

If you already have `sentinel-manage` installed and only want to refresh the agent binary:

```bash
sudo sentinel-manage update latest
```

## Scripts

### Sentinel Agent

- `scripts/manage.sh` — main CLI for managing `sentinel-agent` service, config, and updates
- `scripts/update.sh` — thin wrapper (`manage.sh update ...`)
- `scripts/sentinel-firmware-update` — unprivileged agent-compatible firmware update request wrapper
- `scripts/sentinel-firmware-update-dispatch` — root-owned firmware update dispatcher for the systemd service
- `scripts/install-firmware-updater.sh` — single-file installer for managed firmware update support
- `init.sh` — one-shot bootstrap installer for `sentinel-manage`, `sentinel-agent`, and firmware updater support

## Sentinel Production MCP

The repo also contains a read-only production MCP service under `mcp/`. It is designed to run on a production host, bind only to `127.0.0.1:8787`, and be exposed only through `cloudflared` plus Cloudflare Access.

Supported read operations:

- Kubernetes pod listing, pod logs, pod descriptions, and namespace events for `sentinel`
- Fixed Postgres inspection queries executed via `kubectl exec` into `postgres-0`

### MCP development

```bash
cd mcp
npm install
npm test
npm run build
```

Run locally:

```bash
cd mcp
npm run dev
```

The MCP endpoint is `http://127.0.0.1:8787/mcp`.

### MCP deployment

1. Install Node 20+, `kubectl`, and `cloudflared` on the production host.
2. Copy the `mcp/` directory to the target host and run `npm install && npm run build` inside it.
3. Create a dedicated non-root service user and give it read-only Kubernetes access for namespace `sentinel`, including `pods/log` and the ability to `exec` into `postgres-0`.
4. Substitute the placeholders in `systemd/sentinel-production-mcp.service.in` and install the rendered unit.
5. Configure `cloudflared` using `cloudflared/sentinel-production-mcp.yml.example`.
6. In Cloudflare Zero Trust, protect the MCP hostname with an Access self-hosted application and a service token policy. MCP clients should send `CF-Access-Client-Id` and `CF-Access-Client-Secret`.

The service intentionally does not expose arbitrary shell commands, arbitrary `kubectl`, file reads, or arbitrary SQL.

## Quick run (no install)

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/manage.sh -o /tmp/sentinel-manage.sh
chmod +x /tmp/sentinel-manage.sh
sudo /tmp/sentinel-manage.sh --help
```

## Managed firmware updater install

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/install-firmware-updater.sh -o /tmp/install-firmware-updater.sh
sudo sh /tmp/install-firmware-updater.sh
```

This installs the full root-safe managed firmware update path without requiring `git` on the device:

- `/usr/local/bin/sentinel-manage`
- `/usr/local/bin/sentinel-firmware-update`
- `/usr/local/bin/sentinel-firmware-update-dispatch`
- `sentinel-firmware-update-dispatch.service`
- `sentinel-firmware-update-dispatch.path`
- `/var/lib/sentinel_rtp_cam/firmware-updater/{requests,results}`

If `/usr/local/bin/sentinel-firmware-update` is present, the agent can keep `FIRMWARE_UPDATER_CMD` unset and use the default path.

## Install sentinel-manage only

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/manage.sh -o /usr/local/bin/sentinel-manage
sudo chmod +x /usr/local/bin/sentinel-manage
sentinel-manage --help
```

## Common commands

```bash
# Initialize agent registration payload and server config
sudo sentinel-manage init

# Edit camera/server config JSON
sudo sentinel-manage config camera
sudo sentinel-manage config server

# Service control
sudo sentinel-manage start
sudo sentinel-manage status
sudo sentinel-manage logs

# TLS cert install (agent uses ca.crt; server cert/key/auth.json optional)
sudo sentinel-manage tls --src /tmp

# Update binaries from GitHub releases
sudo sentinel-manage update latest
sudo sentinel-manage update 0.6.4 --dry-run

# Agent-managed firmware jobs after running install-firmware-updater.sh
/usr/local/bin/sentinel-firmware-update 1.1.3
/usr/local/bin/sentinel-firmware-update 1.1.3 --start
/usr/local/bin/sentinel-firmware-update latest
```

Config files used by the scripts:

- `/etc/sentinel_rtp_cam/server.json`
- `/etc/sentinel_rtp_cam/camera.json`
- `/etc/sentinel_rtp_cam/firmware-version`

Agent-managed firmware jobs use `/usr/local/bin/sentinel-firmware-update`. `FIRMWARE_UPDATER_CMD` can remain unset when that default path exists.

Successful updates still run through `sentinel-manage update ...` as root and write the installed firmware version to `/etc/sentinel_rtp_cam/firmware-version` for heartbeat reporting.

The agent-side wrapper is unprivileged. It writes a request into `/var/lib/sentinel_rtp_cam/firmware-updater/requests`, and the root-owned `sentinel-firmware-update-dispatch.path` + `sentinel-firmware-update-dispatch.service` pair performs the actual update.

For `--start` requests, the dispatcher now writes the success result first and then schedules a delayed restart via `systemd-run`, so the agent can report the firmware job as completed before its own service is restarted.

Rollback is not currently implemented by `sentinel-tooling`. `sentinel-firmware-update --rollback` exits nonzero with a clear error instead of pretending success.
