# sentinel-tooling

## Scripts

### Sentinel RTP Camera

- `scripts/manage.sh` — main CLI for managing `sentinel_rtp_cam` services and updates
- `scripts/update.sh` — thin wrapper (`manage.sh update ...`)

## Quick run (no install)

```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/manage.sh -o /tmp/sentinel-manage.sh
chmod +x /tmp/sentinel-manage.sh
sudo /tmp/sentinel-manage.sh --help
```

## Install as system command

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

# Update binaries from GitHub releases
sudo sentinel-manage update latest
sudo sentinel-manage update v0.6.4 --dry-run
```

Config files used by the scripts:

- `/etc/sentinel_rtp_cam/server.json`
- `/etc/sentinel_rtp_cam/camera.json`
