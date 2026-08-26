import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from sqlmodel import SQLModel

from alembic import context

# Make `app` importable regardless of cwd (mirrors how uvicorn/pytest are
# invoked from backend/); this file lives at backend/alembic/env.py.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Import every module that defines a table (table classes register
# themselves on SQLModel.metadata as a side effect of the class body
# executing) *before* reading target_metadata below. All tables currently
# live in app.models.models; see the "grep -rn table=True" check at the
# top of this migration's PR description; if a future PR adds a second
# models module, import it here too or autogenerate will silently miss it.
from app.models import models  # noqa: F401, E402
from app.core.config import settings  # noqa: E402

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Read DATABASE_URL from the same app.core.config.settings the FastAPI app
# uses (issue #58) (not a hardcoded/separate alembic.ini URL) so
# `alembic upgrade head` and the running app always agree on where the DB
# is. alembic.ini's sqlalchemy.url is deliberately left blank; this
# overrides it at runtime. Escape any literal "%" (ConfigParser's
# interpolation character) so passwords containing one don't break parsing.
config.set_main_option(
    "sqlalchemy.url", settings.database_url.replace("%", "%%")
)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = SQLModel.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
