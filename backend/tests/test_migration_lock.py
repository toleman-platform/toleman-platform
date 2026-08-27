"""Regression test for #296: concurrent init_db() calls must not race.

Runs against the real module-level `engine` (whatever DATABASE_URL points
at, a real Postgres in CI's backend-tests job), the same one app/main.py
calls on startup, not a per-test sqlite engine, since the whole point is
to exercise the pg_advisory_lock path in app/core/db.py.
"""

from concurrent.futures import ThreadPoolExecutor

from app.core.db import init_db


def test_concurrent_init_db_calls_do_not_race():
    """Before #296's advisory lock, N concurrent `alembic upgrade head`
    calls against the same fresh-ish DB would race the same DDL and at
    least one would raise (typically a duplicate-type/duplicate-column
    IntegrityError). All of them must now either perform the upgrade or
    find the schema already at head and return cleanly.
    """
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(init_db) for _ in range(6)]
        # .result() re-raises; a single failure here fails the test.
        for future in futures:
            future.result(timeout=60)
