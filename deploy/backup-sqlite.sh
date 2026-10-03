#!/usr/bin/env bash
# Consistent, local SQLite backup for the Starlight API.
# This script does not deploy files or replace anything under /opt/starlight.
set -Eeuo pipefail
umask 077

DATABASE_PATH="${SQLITE_DATABASE_PATH:-/srv/jur10n/data/app.sqlite3}"
BACKUP_DIR="${SQLITE_BACKUP_DIR:-/srv/jur10n/backups/sqlite}"
RETENTION_DAYS="${SQLITE_BACKUP_RETENTION_DAYS:-14}"
LOCK_FILE="${SQLITE_BACKUP_LOCK:-/run/lock/starlight-sqlite-backup.lock}"

fail() {
	printf 'starlight-sqlite-backup: %s\n' "$*" >&2
	exit 1
}

[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || fail "SQLITE_BACKUP_RETENTION_DAYS must be a non-negative integer"
[[ -f "$DATABASE_PATH" ]] || fail "SQLite database does not exist: $DATABASE_PATH"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for the SQLite backup"

install -d -m 0700 -- "$BACKUP_DIR"
install -d -m 0755 -- "$(dirname -- "$LOCK_FILE")"

# Cron normally runs as root. A non-root operator must be able to create the
# configured lock file or explicitly provide SQLITE_BACKUP_LOCK elsewhere.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
	printf 'starlight-sqlite-backup: another backup is already running\n' >&2
	exit 0
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FINAL_PATH="$BACKUP_DIR/starlight-$STAMP.sqlite3"
TEMP_PATH="$(mktemp "$BACKUP_DIR/.starlight-$STAMP.XXXXXX.sqlite3.tmp")"

cleanup() {
	rm -f -- "$TEMP_PATH"
}
trap cleanup EXIT

# Python's standard-library backup API creates a transactionally consistent
# copy while the application may be writing in rollback-journal or WAL mode.
python3 - "$DATABASE_PATH" "$TEMP_PATH" <<'PY'
import sqlite3
import sys

source_path, target_path = sys.argv[1:]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
target = sqlite3.connect(target_path)
try:
    source.backup(target, pages=128, sleep=0.1)
    result = target.execute("PRAGMA quick_check").fetchone()
    if result != ("ok",):
        raise RuntimeError(f"SQLite quick_check failed: {result!r}")
    target.commit()
finally:
    target.close()
    source.close()
PY

chmod 0600 -- "$TEMP_PATH"
mv -- "$TEMP_PATH" "$FINAL_PATH"
printf 'starlight-sqlite-backup: wrote %s\n' "$FINAL_PATH"

# Keep only recent backup files produced by this script.
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'starlight-*.sqlite3' \
	-mtime "+$RETENTION_DAYS" -delete
