#!/usr/bin/env bash
# Back up the Docker Compose deployment's Postgres database (#295: zero
# data loss during upgrades). Run this before `docker compose pull && up
# -d` / `docker compose up --build` on an existing deployment -- an
# Alembic migration is not guaranteed reversible (some in
# backend/alembic/versions/ are, by name, destructive: "drop onboarding
# profile"), so the only real zero-data-loss guarantee is "restore the
# backup taken immediately before the upgrade ran."
#
# Usage: ./scripts/backup-postgres.sh [output-directory]
# Restores with: ./scripts/restore-postgres.sh <backup-file>
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

OUT_DIR="${1:-./backups}"
# umask 077 + explicit chmod 0700: a database dump is as sensitive as the
# database itself. Without this, a common 022 umask leaves the directory
# world-readable (0755) and the dump world-readable (0644), letting any
# other local user read it.
umask 077
mkdir -p "$OUT_DIR"
chmod 0700 "$OUT_DIR"

# Same defaults docker-compose.yml itself falls back to, so this works
# with a bare `docker compose up` and no .env file, the same zero-config
# case the Quickstart promises.
POSTGRES_USER="${POSTGRES_USER:-osp}"
POSTGRES_DB="${POSTGRES_DB:-osp}"

if ! docker compose ps postgres --format json 2>/dev/null | grep -q .; then
  echo "error: the 'postgres' service isn't running (docker compose ps postgres found nothing)." >&2
  echo "Start the stack first: docker compose up -d postgres" >&2
  exit 1
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# mktemp, not a "${OUT_FILE}.partial"-style deterministic name: two backups
# started in the same UTC second would otherwise share one temp path, and
# one process's EXIT trap removing it out from under the other's
# still-writing gzip would corrupt or truncate that backup.
TMP_FILE="$(mktemp "$OUT_DIR/.toleman-${POSTGRES_DB}-${TIMESTAMP}.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT
# OUT_FILE reuses mktemp's own random suffix, for the same reason: without
# it, two backups finishing in the same UTC second would both `mv` to an
# identical OUT_FILE, and the second rename would silently overwrite the
# first's completed, correct backup - the exact "one recovery point is
# gone" failure this script exists to prevent.
UNIQUE_SUFFIX="${TMP_FILE##*.}"
OUT_FILE="$OUT_DIR/toleman-${POSTGRES_DB}-${TIMESTAMP}-${UNIQUE_SUFFIX}.sql.gz"

echo "Backing up '$POSTGRES_DB' (user '$POSTGRES_USER') to $OUT_FILE ..."

# --clean --if-exists: the emitted dump can restore straight over an
# existing (e.g. freshly re-initialized) database instead of only
# working against an empty one, which matters for the actual disaster
# case this script exists for. -Fp (plain SQL) rather than a custom
# archive format so the output is inspectable/greppable without pg_restore.
#
# Written to a .partial temp file and only renamed to OUT_FILE once the
# whole pipeline succeeds (set -o pipefail above makes a pg_dump failure
# fail this line too), so a failed/interrupted backup never leaves behind
# a truncated file that looks like a complete one.
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" --clean --if-exists -Fp "$POSTGRES_DB" \
  | gzip > "$TMP_FILE"
mv "$TMP_FILE" "$OUT_FILE"

SIZE="$(du -h "$OUT_FILE" | cut -f1)"
echo "Backup complete: $OUT_FILE ($SIZE)"
