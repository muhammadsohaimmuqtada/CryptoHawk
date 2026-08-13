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

# Bind integrity verification to the exact archive argument. Do not delegate
# filename selection to sha256sum --check because a modified sidecar could
# otherwise name a different file while the requested archive remained unchecked.
if [[ $(wc -l <"$checksum_path") -ne 1 ]]; then
  echo "backup checksum sidecar must contain exactly one entry" >&2
  exit 65
fi
expected_checksum=$(awk '{print $1}' "$checksum_path")
if [[ ! "$expected_checksum" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "backup checksum sidecar is malformed" >&2
  exit 65
fi
actual_checksum=$(sha256sum -- "$backup_path" | awk '{print $1}')
if [[ "${actual_checksum,,}" != "${expected_checksum,,}" ]]; then
  echo "backup checksum verification failed" >&2
  exit 65
fi

pg_restore --list "$backup_path" >/dev/null

user_relation_count=$(
  psql "$CRYPTOHAWK_POSTGRES_URL" \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --set=ON_ERROR_STOP=1 \
    --command="SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f');"
)

if [[ "$user_relation_count" != "0" ]]; then
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
