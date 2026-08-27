import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlmodel import Session, create_engine
from sqlalchemy import text

from app.core.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(settings.database_url, echo=False)

# backend/alembic.ini, two levels up from this file (app/core/db.py ->
# app/ -> backend/). Resolved absolutely so this works regardless of the
# process's cwd (uvicorn from backend/, pytest from backend/, or the
# Dockerfile's WORKDIR /app which holds the same layout).
_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"

# Arbitrary but fixed id for the pg_advisory_lock below ("Tolem" as bytes,
# comfortably inside bigint's signed range). Picked once and must never
# change: it has no meaning beyond "the same value every `init_db` call
# uses to find the same lock", and changing it would let an old and a new
# backend image run migrations concurrently against each other mid rolling
# deploy.
_MIGRATION_LOCK_ID = 0x546F_6C65_6D


def init_db() -> None:
    """Bring the DB schema up to date via Alembic (issue #58).

    Previously `SQLModel.metadata.create_all(engine)`, which only ever
    creates tables that don't exist yet; it silently no-ops on column/enum
    additions to existing tables, which is exactly how this project's schema
    drifted from models.py in the first place (manual ALTER TABLE/ALTER TYPE
    run by hand against the live DB, tracked nowhere). Running
    `alembic upgrade head` programmatically here instead keeps the
    zero-config "just works locally" startup UX (manual `uvicorn
    app.main:app` and `docker compose up` both still just work, no separate
    migration step to remember) while making every future schema change a
    real, reviewable migration file instead of a hand-run ALTER statement.

    Uses this same process's `settings.database_url` via alembic/env.py
    (not alembic.ini's blank placeholder), so this always targets the exact
    same DB the rest of the app just connected `engine` to above.

    Serialized with a Postgres session-level advisory lock (#296) when the
    target is Postgres. docker-compose.yml only ever starts one `backend`
    replica, but a multi-replica deployment (k8s/Helm, `docker compose up
    --scale backend=N`) has every replica call this on startup; without a
    lock, two processes running `alembic upgrade head` concurrently race the
    same ALTER TABLE/CREATE TYPE statements and one of them errors out
    instead of just waiting its turn. A second replica's call becomes a
    no-op once it gets the lock, since the first has already moved the
    schema to head. Skipped for non-Postgres targets (e.g. the sqlite
    engines the test suite builds directly, which never call this function
    at all, but this stays dialect-safe rather than assuming); sqlite has no
    advisory locks and every test already uses its own isolated in-memory
    database, so there's nothing to race there.
    """
    alembic_cfg = Config(str(_ALEMBIC_INI))
    alembic_cfg.set_main_option("script_location", str(_ALEMBIC_INI.parent / "alembic"))

    if engine.dialect.name != "postgresql":
        command.upgrade(alembic_cfg, "head")
        return

    with engine.connect() as conn:
        logger.info("Acquiring migration lock (id=%s)...", _MIGRATION_LOCK_ID)
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _MIGRATION_LOCK_ID})
        try:
            command.upgrade(alembic_cfg, "head")
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _MIGRATION_LOCK_ID})


def get_session():
    with Session(engine) as session:
        yield session
