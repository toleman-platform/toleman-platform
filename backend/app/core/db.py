from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlmodel import Session, create_engine

from app.core.config import settings

# pool_pre_ping + pool_recycle: see Settings.db_pool_size's docstring
# (app/core/config.py) for why a managed DB needs both, not just the
# bundled docker-compose postgres.
engine = create_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_recycle=settings.db_pool_recycle_seconds,
)

# backend/alembic.ini, two levels up from this file (app/core/db.py ->
# app/ -> backend/). Resolved absolutely so this works regardless of the
# process's cwd (uvicorn from backend/, pytest from backend/, or the
# Dockerfile's WORKDIR /app which holds the same layout).
_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


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
    """
    alembic_cfg = Config(str(_ALEMBIC_INI))
    alembic_cfg.set_main_option("script_location", str(_ALEMBIC_INI.parent / "alembic"))
    command.upgrade(alembic_cfg, "head")


def get_session():
    with Session(engine) as session:
        yield session
