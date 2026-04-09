# xr-jd

XRayR upstream deploy wizard (interactive + CLI).

## Features
- Auto-detect/install XRayR via one-click script
- Prompt for `ApiHost`, `ApiKey`, `NodeID(s)`, `NodeType`, local ports, upstream subscription URL
- Parse subscription (v1 supports `vmess://` lines)
- Generate `config.yml`, `custom_outbound.json`, `route.json`
- `--dry-run` generate only
- `--apply` backup + write `/etc/XrayR` + restart service
- `--rollback` rollback latest backup snapshot

## Quick Start (interactive)
```bash
python3 deploy_xrayr_wizard.py
```

## Quick Start (non-interactive dry-run)
```bash
python3 deploy_xrayr_wizard.py \
  --non-interactive \
  --api-host https://panel.example.com \
  --api-key YOUR_SERVER_TOKEN \
  --node-ids 5 \
  --node-type V2ray \
  --ports 26210 \
  --sub-url 'https://example.com/sub?token=xxx' \
  --dry-run \
  --output-dir ./generated
```

## Apply to system
```bash
sudo python3 deploy_xrayr_wizard.py \
  --non-interactive \
  --api-host https://panel.example.com \
  --api-key YOUR_SERVER_TOKEN \
  --node-ids 5,6 \
  --node-type V2ray \
  --ports 26210-26211 \
  --sub-url 'https://example.com/sub?token=xxx' \
  --apply
```

## Rollback
```bash
sudo python3 deploy_xrayr_wizard.py --rollback
```

## Notes
- Requires root for `--apply` and installer execution.
- Writes to `/etc/XrayR/config.yml`, `/etc/XrayR/custom_outbound.json`, `/etc/XrayR/route.json`.
- Backups saved in `/etc/XrayR/backups/<timestamp>/`.
- Keep `ApiKey` / subscription token private.
