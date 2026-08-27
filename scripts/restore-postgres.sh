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

# The dump itself was taken with --clean --if-exists, so psql tears down
# and recreates every object as it goes; nothing extra needed here beyond
# piping it in.
gunzip -c "$BACKUP_FILE" | docker compose exec -T postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"

echo "Restore complete. Restart the backend/celery-worker so they pick up any"
echo "schema/data change rather than keeping stale cached state:"
echo "  docker compose restart backend celery-worker"
