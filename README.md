# sentinel-tooling

## Scripts

### Sentinel RTP Camera

- `scripts/update.sh` — update `sentinel_rtp_cam` binaries from GitHub releases
- `scripts/manage.sh` — manage `sentinel_rtp_cam` systemd services

Example:
```bash
curl -fsSL https://raw.githubusercontent.com/david-hajnal/sentinel-tooling/main/scripts/update.sh -o /tmp/sentinel-update.sh
chmod +x /tmp/sentinel-update.sh
sudo /tmp/sentinel-update.sh
```
