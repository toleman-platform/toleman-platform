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
mkdir -p "$OUT_DIR"

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
OUT_FILE="$OUT_DIR/toleman-${POSTGRES_DB}-${TIMESTAMP}.sql.gz"

echo "Backing up '$POSTGRES_DB' (user '$POSTGRES_USER') to $OUT_FILE ..."

# --clean --if-exists: the emitted dump can restore straight over an
# existing (e.g. freshly re-initialized) database instead of only
# working against an empty one, which matters for the actual disaster
# case this script exists for. -Fp (plain SQL) rather than a custom
# archive format so the output is inspectable/greppable without pg_restore.
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" --clean --if-exists -Fp "$POSTGRES_DB" \
  | gzip > "$OUT_FILE"

SIZE="$(du -h "$OUT_FILE" | cut -f1)"
echo "Backup complete: $OUT_FILE ($SIZE)"
