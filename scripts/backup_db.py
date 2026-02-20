import argparse
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def backup_database(db_path: Path, backup_dir: Path, daily_keep: int, weekly_keep: int) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"zero_trust_{timestamp}.db"

    src = sqlite3.connect(str(db_path))
    dst = sqlite3.connect(str(backup_path))
    with dst:
        src.backup(dst)
    src.close()
    dst.close()

    backups = sorted(backup_dir.glob("zero_trust_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[daily_keep:]:
        age_days = (datetime.now(timezone.utc) - datetime.fromtimestamp(old.stat().st_mtime, tz=timezone.utc)).days
        if age_days > 7 * weekly_keep:
            old.unlink(missing_ok=True)

    return backup_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hot backup SQLite database with retention.")
    parser.add_argument("--db-path", default=os.getenv("DB_PATH", "data/zero_trust.db"))
    parser.add_argument("--backup-dir", default="backups")
    parser.add_argument("--daily-keep", type=int, default=7)
    parser.add_argument("--weekly-keep", type=int, default=4)
    args = parser.parse_args()

    db_path = Path(args.db_path)
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    path = backup_database(db_path, Path(args.backup_dir), args.daily_keep, args.weekly_keep)
    print(f"Backup created: {path}")
