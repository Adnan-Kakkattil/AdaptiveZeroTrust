# Release Checklist (Single VM)

## Before deployment

- Pull latest code and verify `python -m unittest discover -s tests` passes.
- Create DB backup:
  - `python scripts/backup_db.py --db-path data/zero_trust.db --backup-dir backups`
- Validate `.env` has production-safe values:
  - `APP_ENV=production`
  - strong `SECRET_KEY`
  - `SESSION_COOKIE_SECURE=true`
  - `APP_DEBUG=false`

## Deploy

- Install dependencies:
  - `pip install -r requirements.txt`
- Reload systemd units:
  - `sudo systemctl daemon-reload`
- Restart app:
  - `sudo systemctl restart adaptive-zero-trust.service`

## Post-deploy verification

- Health check:
  - `curl -f https://<host>/api/v1/health`
- Manual login and dashboard load.
- Verify admin policy update succeeds.
- Verify audit export CSV endpoint works.

## Rollback

- Stop service:
  - `sudo systemctl stop adaptive-zero-trust.service`
- Restore backup:
  - `python scripts/restore_db.py --source backups/<backup-file>.db --target data/zero_trust.db`
- Restart service:
  - `sudo systemctl start adaptive-zero-trust.service`
