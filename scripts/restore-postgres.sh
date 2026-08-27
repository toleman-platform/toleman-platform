#!/usr/bin/env bash
# Restore a backup made by scripts/backup-postgres.sh (#295: zero data
# loss during upgrades). Meant for the "the upgrade went wrong, roll
# back" case: an Alembic migration is not guaranteed reversible, so
# rolling the image/commit back alone does not necessarily undo a schema
# change already applied to the running database.
#
# Usage: ./scripts/restore-postgres.sh <backup-file.sql.gz>
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ $# -ne 1 ]; then
  echo "usage: $0 <backup-file.sql.gz>" >&2
  exit 1
fi

BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "error: $BACKUP_FILE does not exist" >&2
  exit 1
fi

POSTGRES_USER="${POSTGRES_USER:-osp}"
POSTGRES_DB="${POSTGRES_DB:-osp}"

if ! gunzip -t "$BACKUP_FILE" 2>/dev/null; then
  echo "error: $BACKUP_FILE is not a valid gzip file (corrupt or truncated download/copy)." >&2
  exit 1
fi

if ! docker compose ps postgres --format json 2>/dev/null | grep -q .; then
  echo "error: the 'postgres' service isn't running (docker compose ps postgres found nothing)." >&2
  echo "Start it first: docker compose up -d postgres" >&2
  exit 1
fi

echo "This will overwrite the current contents of database '$POSTGRES_DB'."
read -r -p "Restore $BACKUP_FILE into it? [y/N] " CONFIRM
case "$CONFIRM" in
  [yY]|[yY][eE][sS]) ;;
  *) echo "Aborted."; exit 1 ;;
esac

# Stop backend/celery-worker first: both hold open connections and the
# backend's own startup hook runs `alembic upgrade head` against this
# same database, either of which can interleave with the restore below
# and leave it half-applied. Left stopped afterward - see the final
# messages - so whoever ran this decides when it's safe to start them
# (e.g. after also rolling the image/commit back, if this restore is
# undoing a migration).
echo "Stopping backend/celery-worker before restoring..."
docker compose stop backend celery-worker

# The dump itself was taken with --clean --if-exists, so psql tears down
# and recreates every object as it goes. ON_ERROR_STOP=on +
# --single-transaction wrap the whole restore in one transaction and abort
# it on the first SQL error, instead of psql's default of plowing on and
# committing whatever ran before the error - which would leave the
# database in an unknown mix of old and new state, exactly what this
# script exists to avoid.
gunzip -c "$BACKUP_FILE" | docker compose exec -T postgres \
  psql -v ON_ERROR_STOP=on --single-transaction -U "$POSTGRES_USER" -d "$POSTGRES_DB"

echo "Restore complete."
echo "backend/celery-worker are still stopped. If this restore is undoing a bad"
echo "upgrade, roll the image/commit back first; either way, start them only"
echo "once you're sure the schema this data expects matches what's about to run"
echo "(the backend runs 'alembic upgrade head' on startup):"
echo "  docker compose up -d backend celery-worker"
