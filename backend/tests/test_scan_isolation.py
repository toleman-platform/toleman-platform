"""Tests for scan workdir isolation (runner.clone_repo) and the Celery retry
policy on scan_tasks.run_scan.

clone_repo previously keyed the destination dir by repo name alone and did an
unconditional rmtree + reclone, so two concurrent scans of the same repo (or
two different targets that happen to share a repo name) would race: one
scan's rmtree could delete files out from under another scan's still-running
clone/tool invocation. These tests prove that scan-scoped identifiers now
produce distinct, non-colliding workdirs, and that the failed clone_repo
call. (No real network access is used -- subprocess.run is monkeypatched.)
"""
import subprocess
from pathlib import Path

import pytest

from app.scanners import runner


def _fake_run_factory(created_marker: str = "MARKER"):
    """Build a stand-in for subprocess.run that fakes `git clone` by creating
    the destination directory (with a marker file) instead of hitting the network.
    """

    def _fake_run(cmd, check=False, capture_output=False, text=False, cwd=None, env=None):
        # cmd looks like ["git", "clone", "--depth", "1", "--branch", branch, "--", url, dest]
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        (dest / created_marker).write_text("cloned")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return _fake_run


@pytest.fixture
def isolated_workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path))
    monkeypatch.setattr(runner.subprocess, "run", _fake_run_factory())
    return tmp_path


def test_clone_repo_scoped_by_scan_id_produces_distinct_paths(isolated_workdir):
    dest_a = runner.clone_repo("https://github.com/acme/widgets.git", "main", scan_id=1)
    dest_b = runner.clone_repo("https://github.com/acme/widgets.git", "main", scan_id=2)

    assert dest_a != dest_b
    assert dest_a.exists()
    assert dest_b.exists()


def test_clone_repo_concurrent_scans_do_not_clobber_each_other(isolated_workdir):
    """Simulates two concurrent scans of the same repo: the second call must not
    delete/overwrite the first scan's checkout (the original race)."""
    dest_a = runner.clone_repo("https://github.com/acme/widgets.git", "main", scan_id="scan-a")
    marker_a = dest_a / "MARKER"
    assert marker_a.exists()

    dest_b = runner.clone_repo("https://github.com/acme/widgets.git", "main", scan_id="scan-b")

    # scan-a's checkout must still be intact after scan-b's clone runs.
    assert marker_a.exists()
    assert dest_a.exists()
    assert dest_b.exists()
    assert dest_a != dest_b


def test_clone_repo_without_scan_id_falls_back_to_unique_uuid(isolated_workdir):
    dest_a = runner.clone_repo("https://github.com/acme/widgets.git", "main")
    dest_b = runner.clone_repo("https://github.com/acme/widgets.git", "main")

    assert dest_a != dest_b
    assert dest_a.exists()
    assert dest_b.exists()


def test_clone_repo_different_targets_same_repo_name_isolated(isolated_workdir):
    """Two different targets whose repo URLs share a basename (e.g. forks) must
    not collide even without an explicit scan_id."""
    dest_a = runner.clone_repo("https://github.com/org-one/widgets.git", "main", scan_id=10)
    dest_b = runner.clone_repo("https://github.com/org-two/widgets.git", "main", scan_id=11)

    assert dest_a != dest_b
    assert dest_a.parent == dest_b.parent  # same workdir root
    assert dest_a.exists() and dest_b.exists()


def test_clone_repo_reclones_into_same_scan_id_dir_if_rerun(isolated_workdir):
    """Retrying the *same* scan (same scan_id) is still expected to clobber its
    own prior partial checkout -- that's not a race since it's sequential."""
    dest_a = runner.clone_repo("https://github.com/acme/widgets.git", "main", scan_id=99)
    (dest_a / "stale.txt").write_text("leftover")

    dest_b = runner.clone_repo("https://github.com/acme/widgets.git", "main", scan_id=99)

    assert dest_a == dest_b
    assert not (dest_b / "stale.txt").exists()
    assert (dest_b / "MARKER").exists()


def test_run_scan_task_has_retry_policy_configured():
    from app.tasks.scan_tasks import run_scan

    assert run_scan.autoretry_for == (subprocess.CalledProcessError,)
    assert run_scan.max_retries == 3
    assert run_scan.retry_backoff is True
