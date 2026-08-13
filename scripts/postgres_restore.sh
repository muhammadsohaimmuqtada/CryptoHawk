#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/postgres_restore.sh BACKUP.dump" >&2
  exit 64
fi

: "${CRYPTOHAWK_POSTGRES_URL:?CRYPTOHAWK_POSTGRES_URL is required}"

backup_path=$1
checksum_path="${backup_path}.sha256"

if [[ ! -f "$backup_path" || ! -f "$checksum_path" ]]; then
  echo "backup archive and .sha256 sidecar are required" >&2
  exit 66
fi

(
  cd -- "$(dirname -- "$backup_path")"
  sha256sum --check --status "$(basename -- "$checksum_path")"
) || {
  echo "backup checksum verification failed" >&2
  exit 65
}

pg_restore --list "$backup_path" >/dev/null

user_table_count=$(
  psql "$CRYPTOHAWK_POSTGRES_URL" \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --set=ON_ERROR_STOP=1 \
    --command="SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema');"
)

if [[ "$user_table_count" != "0" ]]; then
  echo "restore target is not empty; refusing destructive restore" >&2
  exit 73
fi

pg_restore \
  --dbname="$CRYPTOHAWK_POSTGRES_URL" \
  --no-owner \
  --no-privileges \
  --single-transaction \
  --exit-on-error \
  "$backup_path"

printf 'restore_completed=%s\n' "$backup_path"
