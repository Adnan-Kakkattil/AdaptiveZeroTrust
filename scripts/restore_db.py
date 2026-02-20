import argparse
from pathlib import Path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore SQLite database from backup file.")
    parser.add_argument("--source", required=True, help="Backup file path")
    parser.add_argument("--target", default="data/zero_trust.db", help="Target database path")
    args = parser.parse_args()

    source = Path(args.source)
    target = Path(args.target)
    if not source.exists():
        raise SystemExit(f"Backup file not found: {source}")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    print(f"Restored {source} -> {target}")
