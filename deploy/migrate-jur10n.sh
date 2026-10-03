#!/usr/bin/env bash
# Dry-run/checkable migration wrapper. Run backup first; no destructive action.
set -Eeuo pipefail
umask 077
ROOT="${JUR10N_ROOT:-/srv/jur10n}"
DB="${SQLITE_DATABASE_PATH:-$ROOT/data/app.sqlite3}"
FILES="${FILES_ROOT:-$ROOT/data/files}"
MODE="${1:---dry-run}"
[[ "$MODE" == "--dry-run" || "$MODE" == "--apply" ]] || { printf 'usage: %s [--dry-run|--apply]\n' "$0" >&2; exit 2; }
[[ -f "$DB" ]] || { printf 'database missing: %s\n' "$DB" >&2; exit 1; }
printf '%s\n' "database=$DB" "files=$FILES" "mode=$MODE"
python3 - "$DB" <<'PY'
import sqlite3, sys
path=sys.argv[1]
con=sqlite3.connect(f"file:{path}?mode=ro", uri=True)
try:
    tables={row[0] for row in con.execute("select name from sqlite_master where type='table'")}
    required={'schema_migrations','software_slots','software_keys','license_codes','data_slots','data_uploads'}
    print('tables_present=' + str(len(tables)))
    print('missing=' + ','.join(sorted(required-tables)))
    print('quick_check=' + str(con.execute('pragma quick_check').fetchone()[0]))
finally: con.close()
PY
if [[ "$MODE" == "--dry-run" ]]; then
  printf '%s\n' 'dry-run complete; no changes made'
  exit 0
fi
printf '%s\n' 'apply mode is intentionally not destructive; start the API to run idempotent migrations'
