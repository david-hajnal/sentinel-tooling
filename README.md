# sentinel-tooling

## Scripts

### Sentinel RTP Camera

- `scripts/manage.sh` — main CLI for managing `sentinel_rtp_cam` services and updates
- `scripts/update.sh` — thin wrapper (`manage.sh update ...`)
- `scripts/sentinel-firmware-update` — agent-compatible firmware updater wrapper (`sentinel-manage update ...`)

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

## Install as system command

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/manage.sh -o /usr/local/bin/sentinel-manage
sudo chmod +x /usr/local/bin/sentinel-manage
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/sentinel-firmware-update -o /usr/local/bin/sentinel-firmware-update
sudo chmod +x /usr/local/bin/sentinel-firmware-update
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

# Agent-managed firmware jobs
sudo /usr/local/bin/sentinel-firmware-update 1.1.3
sudo /usr/local/bin/sentinel-firmware-update 1.1.3 --start
sudo /usr/local/bin/sentinel-firmware-update latest
```

Config files used by the scripts:

- `/etc/sentinel_rtp_cam/server.json`
- `/etc/sentinel_rtp_cam/camera.json`
- `/etc/sentinel_rtp_cam/firmware-version`

Agent-managed firmware jobs should point `FIRMWARE_UPDATER_CMD` at `/usr/local/bin/sentinel-firmware-update`.

Successful updates write the installed firmware version to `/etc/sentinel_rtp_cam/firmware-version` for heartbeat reporting.

Rollback is not currently implemented by `sentinel-tooling`. `sentinel-firmware-update --rollback` exits nonzero with a clear error instead of pretending success.
