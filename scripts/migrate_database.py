"""Back up an existing SQLite database, then apply forward-only schema upgrades.

For PostgreSQL, take a pg_dump backup before running this command.
Stop application workers during schema upgrades.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.db import bind_organization, engine, init_db  # noqa: E402
from scripts.backup_sqlite import backup  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, help="Required backup destination for an existing SQLite database")
    parser.add_argument("--organization-id", help="Permanently bind this dedicated database to an organization")
    args = parser.parse_args()
    if engine.dialect.name == "sqlite" and engine.url.database != ":memory:":
        source = Path(engine.url.database)
        if source.exists():
            if args.backup is None or args.backup.exists() or args.backup.resolve() == source.resolve():
                parser.error("Choose a new --backup path for the existing SQLite database")
            backup(source, args.backup)
            print(f"Backup saved to {args.backup}")
    init_db()
    if args.organization_id:
        bind_organization(args.organization_id)
    print("Schema upgrade complete.")


if __name__ == "__main__":
    main()
