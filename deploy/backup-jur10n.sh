#!/usr/bin/env bash
# Create a consistent, local backup of the SQLite database and software files.
# The script never touches /opt/starlight and never uploads data externally.
set -Eeuo pipefail
umask 077

DATABASE_PATH="${SQLITE_DATABASE_PATH:-/srv/jur10n/data/app.sqlite3}"
FILES_ROOT="${FILES_ROOT:-/srv/jur10n/data/files}"
BACKUP_DIR="${SQLITE_BACKUP_DIR:-/srv/jur10n/backups/sqlite}"
RETENTION_DAYS="${SQLITE_BACKUP_RETENTION_DAYS:-14}"
LOCK_FILE="${SQLITE_BACKUP_LOCK:-/run/lock/jur10n-backup.lock}"

fail() { printf 'jur10n-backup: %s\n' "$*" >&2; exit 1; }
[[ -f "$DATABASE_PATH" ]] || fail "SQLite database does not exist: $DATABASE_PATH"
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || fail "retention must be a non-negative integer"
command -v python3 >/dev/null || fail "python3 is required"
install -d -m 0700 "$BACKUP_DIR" "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || { printf '%s\n' 'jur10n-backup: another backup is running'; exit 0; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE="$(mktemp -d "$BACKUP_DIR/.jur10n-$STAMP.XXXXXX")"
cleanup() { rm -rf -- "$STAGE"; }
trap cleanup EXIT
python3 - "$DATABASE_PATH" "$STAGE/app.sqlite3" <<'PY'
import sqlite3, sys
source_path, target_path = sys.argv[1:]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
target = sqlite3.connect(target_path)
try:
    source.backup(target, pages=128, sleep=0.1)
    if target.execute("PRAGMA quick_check").fetchone() != ("ok",):
        raise RuntimeError("SQLite quick_check failed")
    target.commit()
finally:
    target.close(); source.close()
PY
chmod 0600 "$STAGE/app.sqlite3"
if [[ -d "$FILES_ROOT" ]]; then
  tar -C "$FILES_ROOT" -czf "$STAGE/files.tar.gz" .
  chmod 0600 "$STAGE/files.tar.gz"
fi
printf '%s\n' "$STAMP" > "$STAGE/manifest.txt"
chmod 0600 "$STAGE/manifest.txt"
FINAL="$BACKUP_DIR/jur10n-$STAMP"
mv "$STAGE" "$FINAL"
find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'jur10n-*' -mtime "+$RETENTION_DAYS" -exec rm -rf -- {} +
printf 'jur10n-backup: wrote %s\n' "$FINAL"
