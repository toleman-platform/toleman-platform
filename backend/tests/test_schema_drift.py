"""Pins the model/schema facts behind issue #217.

`alembic revision --autogenerate` diffs `SQLModel.metadata` against a live
database, so anything the database has and metadata does not reads to it as a
deletion. #217 is a generated migration that, among routine operations,
wanted to `drop_table('discoveredendpoint')` and
`drop_index('ix_aibomcomponent_upsert_key')`. `init_db()` runs
`alembic upgrade head` on startup, so committing that unread would have run
both on deploy.

The two have opposite causes, and this file pins both so neither can drift
back silently.

`ix_aibomcomponent_upsert_key` is a real object that a migration in the chain
created (3d006423f58b) and that `app.core.aibom` depends on: it is the upsert
key. The model simply never declared it, so metadata could not account for it
and autogenerate proposed removing it. That is a genuine bug in the model, and
it is fixed -- `AiBomComponent.__table_args__` now declares the index. The
tests below hold the model and the migration to the same definition.

`discoveredendpoint` is the opposite: autogenerate is right about it. There is
no `DiscoveredEndpoint` model anywhere in the tree, no migration in the chain
ever created the table, and API Discovery's live data is in `apiendpoint`
(`ApiEndpoint` in app/models/models.py, written by
`app.core.discovery_ingestion.upsert_endpoints`, created by the initial
revision 404553cc4bf6). The old table is an orphan from the pre-Alembic
`SQLModel.metadata.create_all()` era. Nothing here is broken, so nothing here
is fixed; what these tests pin is the shape of the answer, so that a future
reader does not "repair" the drift by inventing a model for a dead table.
Whether the orphan can actually be dropped is a live-data question -- do the
deployed rows have counterparts in `apiendpoint`? -- and the audit for it is
tracked in #438.

Pure metadata assertions: no database, no engine, no migrations run.
"""
import ast
from pathlib import Path

from sqlmodel import SQLModel

from app.models import models  # noqa: F401  -- registers tables on the metadata

BACKEND = Path(__file__).resolve().parents[1]
VERSIONS = BACKEND / "alembic" / "versions"
AIBOM_MIGRATION = VERSIONS / "3d006423f58b_add_aibom_components_190.py"


def _table_operations() -> set[tuple[str, str, str]]:
    """Every `op.<something>('<literal>', ...)` call across the migration
    chain, as (revision filename, call name, first string argument).

    Parsed rather than grepped on purpose. Several migration docstrings
    quote `drop_table('discoveredendpoint')` verbatim while explaining why
    they refused to ship it -- 506252dfc555's is the fullest account -- so a
    substring search would flag the prose that documents the problem as if
    it were the problem. Only real calls count.
    """
    found = set()
    for migration in sorted(VERSIONS.glob("*.py")):
        tree = ast.parse(migration.read_text(), filename=str(migration))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            first = node.args[0]
            if name and isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add((migration.name, name, first.value))
    return found


def _index(table_name: str, index_name: str):
    table = SQLModel.metadata.tables[table_name]
    for index in table.indexes:
        if index.name == index_name:
            return index
    raise AssertionError(
        f"{table_name} has no index named {index_name}; "
        f"found {sorted(i.name for i in table.indexes)}"
    )


# ---------------------------------------------------------------------------
# aibomcomponent -- the index autogenerate wanted to drop, and shouldn't have.
# ---------------------------------------------------------------------------


def test_aibomcomponent_is_in_the_metadata():
    assert "aibomcomponent" in SQLModel.metadata.tables


def test_aibomcomponent_upsert_index_is_declared_on_the_model():
    """The drop #217 caught. 3d006423f58b creates this index and
    `app.core.aibom.upsert_aibom_components` keys on exactly these columns, so
    it has to be in metadata too; an index that exists only in the database
    is an index Alembic will offer to delete."""
    index = _index("aibomcomponent", "ix_aibomcomponent_upsert_key")

    assert index.unique is True
    # Order matters to Alembic's comparison as much as to the index itself.
    assert [c.name for c in index.columns] == ["target_id", "branch", "name", "component_type"]


def test_aibomcomponent_target_id_index_is_declared_on_the_model():
    assert _index("aibomcomponent", "ix_aibomcomponent_target_id").unique is not True


def test_aibomcomponent_model_and_migration_agree_on_the_upsert_index():
    """A model declaration that has quietly drifted from the migration that
    built the index is the same failure wearing a different hat."""
    source = AIBOM_MIGRATION.read_text()
    assert "ix_aibomcomponent_upsert_key" in source
    for column in ("target_id", "branch", "name", "component_type"):
        assert f'"{column}"' in source


# ---------------------------------------------------------------------------
# discoveredendpoint -- an orphan table, not a model that went missing.
# ---------------------------------------------------------------------------


def test_apiendpoint_is_the_live_api_discovery_table():
    """`ApiEndpoint` is what API Discovery reads and writes, and
    404553cc4bf6 creates `apiendpoint` with this index. This is the table the
    feature actually uses -- the reason `discoveredendpoint` is dead weight
    rather than something to restore."""
    assert "apiendpoint" in SQLModel.metadata.tables
    _index("apiendpoint", "ix_apiendpoint_target_id")


def test_discoveredendpoint_has_no_model_and_no_migration():
    """Autogenerate is *correct* that this table corresponds to nothing. It
    is an orphan left in deployed databases by the pre-Alembic
    `SQLModel.metadata.create_all()` era, superseded by `apiendpoint`.

    The failure mode this guards against is someone reading a generated
    `drop_table('discoveredendpoint')`, assuming Alembic is confused about a
    rename, and "fixing" it by adding a model or a `__tablename__` override
    for a table no code path touches. That would resurrect a dead schema and
    make the real question -- whether the deployed rows were ever carried
    over into `apiendpoint` -- harder to ask, not easier.
    """
    assert "discoveredendpoint" not in SQLModel.metadata.tables

    creators = [
        revision
        for revision, call, table in _table_operations()
        if call == "create_table" and table == "discoveredendpoint"
    ]
    assert creators == [], f"a migration now creates discoveredendpoint: {creators}"


def test_no_migration_drops_discoveredendpoint():
    """Dropping it may well be the right end state -- it is superseded and
    unreferenced -- but not before someone has counted the rows in a real
    deployment and checked them against `apiendpoint`. Until that audit has
    run, a drop must not be in the chain: `init_db()` runs
    `alembic upgrade head` on startup, so it would execute itself on the
    next deploy rather than at a moment anyone had chosen."""
    droppers = [
        revision
        for revision, call, table in _table_operations()
        if call == "drop_table" and table == "discoveredendpoint"
    ]
    assert droppers == [], f"a migration now drops discoveredendpoint: {droppers}"


# ---------------------------------------------------------------------------
# finding / scan -- the indexes b1d4f7a09c62 backfills onto drifted databases.
# ---------------------------------------------------------------------------


def test_finding_and_scan_query_indexes_are_declared():
    """These are the columns the codebase filters by constantly. The models
    declare them and 404553cc4bf6 creates them; b1d4f7a09c62 backfills them
    onto databases that predate the migration chain. If a name here stops
    matching, that backfill quietly creates a second index under a different
    name instead of finding the existing one."""
    for name in (
        "ix_finding_target_id",
        "ix_finding_branch",
        "ix_finding_priority_score",
        "ix_finding_state",
    ):
        _index("finding", name)

    _index("scan", "ix_scan_target_id")
