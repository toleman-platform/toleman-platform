"""Shared test setup.

Both fixtures here exist for #229, which gave the scanner runner two things
it did not have before: a per-run tool cache on disk, and a warm-up step
that shells out to trivy to download a vulnerability database. Neither
belongs in a unit-test run.
"""

import pytest

from app.core.config import settings
from app.scanners import runner


@pytest.fixture(autouse=True)
def _isolated_tool_cache(tmp_path_factory, monkeypatch):
    """Keep per-run scanner caches inside the test's own tmp directory.

    ``runner.run_tool`` now creates a cache under ``settings.tool_cache_dir``
    for trivy and semgrep. Left at its default that is a real path on the
    machine running the tests, so every test that exercises a scanner would
    create -- and, on a killed run, leave behind -- directories outside the
    sandbox. Pointing it at tmp_path per test also makes the cache
    assertions in test_scan_health.py mean something, rather than depending
    on whatever the host already had cached.
    """
    cache_dir = tmp_path_factory.mktemp("tool-cache")
    monkeypatch.setattr(settings, "tool_cache_dir", str(cache_dir))
    return cache_dir


@pytest.fixture(autouse=True)
def _no_database_warming(monkeypatch):
    """Never download a vulnerability database from a test.

    ``ensure_warm_trivy_db`` is called by ``run_scan`` and by the PR
    Guardrail executor, both of which several test modules drive with trivy
    in the tool list. On a developer machine that actually has trivy
    installed, the real function would shell out and fetch hundreds of
    megabytes mid-suite; on CI it would fail slowly instead. Neither is what
    those tests are checking.

    Tests that are specifically about warming call the real implementation
    directly (see test_scan_health.py, which captures it at import time), and
    tests about the call *site* patch this same attribute with their own
    spy -- both of which take precedence over this stub.
    """
    monkeypatch.setattr(
        runner, "ensure_warm_trivy_db", lambda *args, **kwargs: (False, "warming disabled in tests")
    )
