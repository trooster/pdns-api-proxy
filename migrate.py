#!/usr/bin/env python3
"""
Database migration runner for PDNS API Proxy.

Usage:
  python migrate.py status        # Show applied/pending migrations
  python migrate.py up            # Apply all pending migrations
  python migrate.py down          # Roll back the last applied migration
  python migrate.py down N        # Roll back the last N applied migrations

Migration files live in migrations/ and follow the naming convention:
  NNN_description.up.sql    — forward migration
  NNN_description.down.sql  — rollback (required)

The script tracks applied migrations in the schema_migrations table,
which is bootstrapped automatically on first run.
"""

import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    migration    VARCHAR(255) NOT NULL,
    applied_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_schema_migrations_migration (migration)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def load_env():
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())


def get_connection():
    import pymysql

    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("ERROR: DATABASE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    # Strip driver prefix: mysql+pymysql:// → mysql://
    url = re.sub(r"^[^:]+\+", "", url)
    parsed = urlparse(url)

    return pymysql.connect(
        host=parsed.hostname,
        port=parsed.port or 3306,
        user=parsed.username,
        password=parsed.password,
        database=parsed.path.lstrip("/"),
        charset="utf8mb4",
        autocommit=False,
    )


def discover_migrations():
    """Return sorted list of migration names (e.g. '001_initial')."""
    names = set()
    for f in MIGRATIONS_DIR.glob("*.up.sql"):
        names.add(f.stem.removesuffix(".up"))
    return sorted(names)


def applied_migrations(cursor):
    cursor.execute("SELECT migration FROM schema_migrations ORDER BY migration")
    return {row[0] for row in cursor.fetchall()}


def run_sql_file(cursor, path):
    sql = path.read_text()
    # Split on semicolons, skip empty statements
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    for stmt in statements:
        cursor.execute(stmt)


def cmd_status(cursor):
    available = discover_migrations()
    applied = applied_migrations(cursor)

    print(f"{'Migration':<40} {'Status'}")
    print("-" * 50)
    for name in available:
        status = "applied" if name in applied else "pending"
        print(f"{name:<40} {status}")

    pending = [n for n in available if n not in applied]
    print()
    print(f"{len(applied)} applied, {len(pending)} pending")


def cmd_up(conn, cursor):
    available = discover_migrations()
    applied = applied_migrations(cursor)
    pending = [n for n in available if n not in applied]

    if not pending:
        print("Nothing to do — all migrations already applied.")
        return

    for name in pending:
        up_file = MIGRATIONS_DIR / f"{name}.up.sql"
        down_file = MIGRATIONS_DIR / f"{name}.down.sql"

        if not down_file.exists():
            print(f"ERROR: {name}.down.sql is missing — refusing to apply without a rollback.", file=sys.stderr)
            sys.exit(1)

        print(f"Applying {name}...")
        try:
            run_sql_file(cursor, up_file)
            cursor.execute(
                "INSERT INTO schema_migrations (migration) VALUES (%s)", (name,)
            )
            conn.commit()
            print(f"  OK")
        except Exception as e:
            conn.rollback()
            print(f"  FAILED: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"\nDone. Applied {len(pending)} migration(s).")


def cmd_down(conn, cursor, steps=1):
    applied = sorted(applied_migrations(cursor), reverse=True)

    if not applied:
        print("Nothing to roll back — no migrations have been applied.")
        return

    to_rollback = applied[:steps]

    for name in to_rollback:
        down_file = MIGRATIONS_DIR / f"{name}.down.sql"
        if not down_file.exists():
            print(f"ERROR: {name}.down.sql not found.", file=sys.stderr)
            sys.exit(1)

        print(f"Rolling back {name}...")
        try:
            run_sql_file(cursor, down_file)
            cursor.execute(
                "DELETE FROM schema_migrations WHERE migration = %s", (name,)
            )
            conn.commit()
            print(f"  OK")
        except Exception as e:
            conn.rollback()
            print(f"  FAILED: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"\nDone. Rolled back {len(to_rollback)} migration(s).")


def main():
    load_env()
    conn = get_connection()
    cursor = conn.cursor()

    # Bootstrap the tracking table
    cursor.execute(BOOTSTRAP_SQL)
    conn.commit()

    args = sys.argv[1:]
    if not args or args[0] == "status":
        cmd_status(cursor)
    elif args[0] == "up":
        cmd_up(conn, cursor)
    elif args[0] == "down":
        steps = int(args[1]) if len(args) > 1 else 1
        cmd_down(conn, cursor, steps)
    else:
        print(__doc__)
        sys.exit(1)

    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()
