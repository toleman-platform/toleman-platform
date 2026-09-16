"""Per-workspace GitHub App registration (#506)

A workspace may now register its own GitHub App instead of always sharing
the platform-wide one. Nullable, no backfill: every existing
GitHubAppConfig row stays NULL, which is the correct reading -- it becomes
the platform-level default App every workspace that hasn't registered its
own continues to use.

Two partial-unique indexes, not one plain index, enforce the two real
invariants a plain `UNIQUE(workspace_id)` cannot: at most one App per
workspace (ordinary partial unique, `WHERE workspace_id IS NOT NULL`), and
separately at most one platform-default row (`WHERE workspace_id IS NULL`)
-- a plain unique constraint never conflicts on NULL, every SQL dialect
treats each NULL as distinct from every other, so it would silently allow
any number of platform-default rows. The second index is unique on a
constant expression restricted by that WHERE clause specifically so a real
equality check applies among the rows it covers, instead of comparing NULLs
to each other. `app/api/github_app.py`'s `callback()` handles the resulting
`IntegrityError` on a race (two concurrent manifest flows for the same
scope) by rolling back and reporting the conflict rather than 500ing.

Deliberately NOT mirrored in `GitHubAppConfig.__table_args__`: the model's
defensive resolution logic
(`app.core.github_app.resolve_config_for_installation`) is exercised
against SQLite-backed unit tests that construct exactly the ambiguous rows
these indexes forbid on Postgres, to pin how that logic behaves against
data that predates this migration (or reached the table by some other
path than this API). Declaring the same constraint on the model would make
those fixtures un-insertable and remove that coverage. A future
`alembic revision --autogenerate` will therefore propose dropping both
indexes as unaccounted-for in metadata -- known drift, not a bug; do not
apply that migration.

Revision ID: f589f48b137b
Revises: b6d2f8a41c79
"""
import sqlalchemy as sa
from alembic import op

revision = "f589f48b137b"
down_revision = "b6d2f8a41c79"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("githubappconfig", sa.Column("workspace_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_githubappconfig_workspace_id",
        "githubappconfig",
        "workspace",
        ["workspace_id"],
        ["id"],
    )
    op.create_index(
        "ix_githubappconfig_workspace_id",
        "githubappconfig",
        ["workspace_id"],
        unique=True,
        postgresql_where=sa.text("workspace_id IS NOT NULL"),
        sqlite_where=sa.text("workspace_id IS NOT NULL"),
    )
    op.create_index(
        "ix_githubappconfig_one_platform_default",
        "githubappconfig",
        [sa.text("(1)")],
        unique=True,
        postgresql_where=sa.text("workspace_id IS NULL"),
        sqlite_where=sa.text("workspace_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_githubappconfig_one_platform_default", table_name="githubappconfig")
    op.drop_index("ix_githubappconfig_workspace_id", table_name="githubappconfig")
    op.drop_constraint("fk_githubappconfig_workspace_id", "githubappconfig", type_="foreignkey")
    op.drop_column("githubappconfig", "workspace_id")
