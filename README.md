# sentinel-tooling

## Scripts

### Sentinel RTP Camera

- `scripts/manage.sh` — main CLI for managing `sentinel_rtp_cam` services and updates
- `scripts/update.sh` — thin wrapper (`manage.sh update ...`)
- `scripts/sentinel-firmware-update` — unprivileged agent-compatible firmware update request wrapper
- `scripts/sentinel-firmware-update-dispatch` — root-owned firmware update dispatcher for the systemd service
- `scripts/install-firmware-updater.sh` — single-file installer for managed firmware update support

## Quick run (no install)

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/manage.sh -o /tmp/sentinel-manage.sh
chmod +x /tmp/sentinel-manage.sh
sudo /tmp/sentinel-manage.sh --help
```

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/init.sh -o /tmp/sentinel-init.sh && sudo bash /tmp/sentinel-init.sh
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
# Initialize agent registration payload
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
