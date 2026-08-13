#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/postgres_backup.sh BACKUP.dump" >&2
  exit 64
fi

: "${CRYPTOHAWK_POSTGRES_URL:?CRYPTOHAWK_POSTGRES_URL is required}"

backup_path=$1
backup_dir=$(dirname -- "$backup_path")
backup_name=$(basename -- "$backup_path")
mkdir -p -- "$backup_dir"
umask 077

tmp_path=$(mktemp "${backup_dir}/.${backup_name}.tmp.XXXXXX")
cleanup() {
  rm -f -- "$tmp_path"
}
trap cleanup EXIT INT TERM

pg_dump \
  --dbname="$CRYPTOHAWK_POSTGRES_URL" \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file="$tmp_path"

# Fail before publishing a backup that pg_restore cannot parse.
pg_restore --list "$tmp_path" >/dev/null

mv -- "$tmp_path" "$backup_path"
(
  cd -- "$backup_dir"
  sha256sum "$backup_name" >"${backup_name}.sha256"
)
chmod 600 "$backup_path" "${backup_path}.sha256"
trap - EXIT INT TERM

printf 'backup_created=%s\n' "$backup_path"
