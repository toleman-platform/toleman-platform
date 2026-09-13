"""Concurrent scans must not produce a false all-clear (#229).

The reproduction: six scans dispatched together, all running trivy against
one shared vulnerability-DB cache. One of them read the DB while another was
replacing it and came back with exit code 0, valid JSON and no
vulnerabilities for a repository with five live High/Medium CVEs.
``ingest_findings`` could not tell that apart from "scanned it, it's clean",
so it marked all five ``Mitigated``. The same scan run alone four minutes
later found all five and reopened them.

Two defects, and this file covers both:

  1. Concurrent same-tool runs racing shared mutable tool state. Toleman now
     keeps its own warm copy of the trivy DB, published by replacing a whole
     directory under a lock, and each run hardlinks a private cache out of
     it and scans with --skip-db-update.

  2. The more important one: a zero-finding result being trusted
     unconditionally. Zero vulnerabilities is accepted as a clean result
     only when the database behind the run is positively verified -- a real
     file of a plausible size, metadata that parses, not long past its own
     refresh deadline, and unchanged across the run. That is the evidence
     #229's reproduction could not have produced, whether it surfaced as an
     empty Results list or as Results carrying empty Vulnerabilities.

The rule the whole file is checking:

    ran, found nothing          a real clean result; may mitigate
    ran, but may not have       ScanHealth suspect; mitigates nothing
    did not run / broke         ToolNotApplicable / ToolExecutionError (#243, #253)
"""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.core.dedup import compute_dedup_hash
from app.core.ingestion import ingest_findings
from app.core.scan_health import HEALTHY, SUSPECT, UNKNOWN, ScanHealth, trusted
from app.models.models import (
    Finding,
    FindingState,
    Organization,
    Scan,
    Severity,
    Target,
    Workspace,
)
from app.scanners import runner
from app.scanners.parsers import sarif_health


# conftest.py stubs ensure_warm_trivy_db out for the whole suite (it shells
# out to trivy and downloads hundreds of megabytes). The tests below are the
# ones actually about warming, so they hold the real implementation, captured
# here at import time before that autouse fixture can replace it.
_REAL_ENSURE_WARM = runner.ensure_warm_trivy_db


def _ctx(tool: str = "trivy", **kwargs) -> runner.ScanRunContext:
    return runner.ScanRunContext(tool=tool, health=ScanHealth(tool=tool), **kwargs)


def _write_trivy_db(
    cache_dir: Path,
    *,
    next_update: str | None = None,
    size: int = runner.MIN_TRIVY_DB_BYTES + 1,
    version: int | None = 2,
    db_file: bool = True,
) -> Path:
    """Build a cache directory that looks like one trivy just populated.

    The DB file is made sparse rather than written byte by byte: the checks
    under test read its *size*, and a real one is hundreds of megabytes.
    """
    db = cache_dir / "db"
    db.mkdir(parents=True, exist_ok=True)
    if db_file:
        with open(db / "trivy.db", "wb") as handle:
            handle.truncate(size)
    payload: dict = {}
    if version is not None:
        payload["Version"] = version
    payload["NextUpdate"] = next_update or (
        (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
    )
    (db / "metadata.json").write_text(json.dumps(payload))
    return cache_dir


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


# ---------------------------------------------------------------------------
# The signal itself
# ---------------------------------------------------------------------------


class TestScanHealth:
    def test_a_fresh_health_is_healthy(self):
        """Healthy is the *absence* of any reason to doubt the run, not a
        default assumption baked into the type: nothing sets it True."""
        assert ScanHealth(tool="trivy").healthy is True
        assert ScanHealth(tool="trivy").status == HEALTHY

    def test_one_reason_makes_it_suspect(self):
        health = ScanHealth(tool="trivy")
        health.degrade("vulnerability database was missing")
        assert health.healthy is False
        assert health.status == SUSPECT
        assert "vulnerability database" in health.summary()

    def test_repeated_reasons_are_recorded_once(self):
        """A PER_FILE tool is invoked once per changed file and can emit the
        same warning on every one of them; the note must stay readable."""
        health = ScanHealth(tool="gitleaks")
        for _ in range(20):
            health.degrade("failed to download")
        assert health.reasons == ["failed to download"]

    def test_the_note_is_bounded(self):
        health = ScanHealth(tool="trivy")
        for i in range(200):
            health.degrade(f"reason number {i} with some padding text")
        assert len(health.summary()) <= 500

    def test_trusted_is_healthy(self):
        assert trusted("api-scan").healthy is True


class TestStderrWarnings:
    """#253 taught this codebase that a crashed scanner must not read as a
    clean pass. This is the same lesson one notch quieter: the tool did not
    crash, and the only evidence is a line it wrote on the way past."""

    def test_a_download_failure_makes_the_run_suspect(self):
        health = ScanHealth(tool="trivy")
        runner._note_stderr("trivy", "2026-08-22 WARN failed to download vulnerability DB", health)
        assert health.healthy is False
        assert "trivy" in health.summary()

    def test_ordinary_chatter_leaves_the_run_healthy(self):
        """A marker list that flags every run teaches operators that
        'suspect' means nothing, which is worse than not having the signal:
        a suspect run blocks auto-mitigation, and a signal nobody believes
        gets switched off."""
        health = ScanHealth(tool="trivy")
        runner._note_stderr(
            "trivy",
            "INFO Vulnerability scanning is enabled\nINFO Number of language-specific files: 3",
            health,
        )
        assert health.healthy is True

    def test_empty_stderr_leaves_the_run_healthy(self):
        health = ScanHealth(tool="trivy")
        runner._note_stderr("trivy", "", health)
        assert health.healthy is True

    def test_a_single_unreadable_file_does_not_taint_the_whole_run(self):
        """Deliberately absent from the marker list: an ordinary repo with a
        broken symlink or an unreadable binary would otherwise be stuck
        never able to mitigate anything, which is its own kind of dishonesty
        about the state of the repo."""
        health = ScanHealth(tool="semgrep")
        runner._note_stderr("semgrep", "WARN open vendor/x.so: no such file or directory", health)
        assert health.healthy is True

    def test_colour_codes_do_not_hide_a_warning(self):
        health = ScanHealth(tool="trivy")
        runner._note_stderr("trivy", "\x1b[33mWARN\x1b[0m Failed To Download the DB", health)
        assert health.healthy is False


class TestTrivyDatabaseState:
    """The evidence that decides whether zero vulnerabilities may be read as
    a clean repository. It checks the database *file*, not just the metadata
    beside it: a cache caught mid-replacement can carry perfectly parseable
    metadata next to a trivy.db that is missing or half-written, and
    metadata alone would wave that through -- which is how #229's
    reproduction reported clean."""

    def test_a_complete_fresh_database_is_usable(self, tmp_path):
        _write_trivy_db(tmp_path)
        ok, reason = runner.trivy_db_state(tmp_path)
        assert ok is True and reason == ""

    def test_no_database_file_at_all(self, tmp_path):
        _write_trivy_db(tmp_path, db_file=False)
        ok, reason = runner.trivy_db_state(tmp_path)
        assert ok is False
        assert "no vulnerability database file" in reason

    def test_a_truncated_database_is_not_usable(self, tmp_path):
        """The shape a mid-download or mid-replacement read leaves behind.
        Metadata parses, NextUpdate is in the future, and the file is a
        stub -- exactly the combination that used to pass."""
        _write_trivy_db(tmp_path, size=4096)
        ok, reason = runner.trivy_db_state(tmp_path)
        assert ok is False
        assert "far short of a complete one" in reason

    def test_missing_metadata_is_not_usable(self, tmp_path):
        _write_trivy_db(tmp_path)
        (tmp_path / "db" / "metadata.json").unlink()
        ok, _ = runner.trivy_db_state(tmp_path)
        assert ok is False

    def test_unreadable_metadata_is_not_usable(self, tmp_path):
        _write_trivy_db(tmp_path)
        (tmp_path / "db" / "metadata.json").write_text("{not json")
        ok, _ = runner.trivy_db_state(tmp_path)
        assert ok is False

    def test_metadata_without_a_schema_version_is_not_usable(self, tmp_path):
        _write_trivy_db(tmp_path, version=None)
        ok, _ = runner.trivy_db_state(tmp_path)
        assert ok is False

    def test_a_database_long_past_its_refresh_deadline_is_not_usable(self, tmp_path):
        stale = datetime.now(timezone.utc) - timedelta(hours=runner.TRIVY_DB_STALE_GRACE_HOURS + 48)
        _write_trivy_db(tmp_path, next_update=stale.isoformat().replace("+00:00", "Z"))
        ok, reason = runner.trivy_db_state(tmp_path)
        assert ok is False
        assert "refresh deadline" in reason

    def test_a_database_just_past_its_deadline_is_still_usable(self, tmp_path):
        """NextUpdate passing is routine -- trivy publishes every few hours
        and refreshes opportunistically. Only a refresh that has been
        failing for days says anything about the result."""
        recent = datetime.now(timezone.utc) - timedelta(hours=2)
        _write_trivy_db(tmp_path, next_update=recent.isoformat().replace("+00:00", "Z"))
        ok, _ = runner.trivy_db_state(tmp_path)
        assert ok is True

    def test_go_nanosecond_timestamps_parse(self):
        """trivy is Go, so it writes nanosecond precision, which
        datetime.fromisoformat rejects outright."""
        parsed = runner._parse_trivy_timestamp("2026-08-22T12:03:37.123456789Z")
        assert parsed is not None
        assert parsed.year == 2026 and parsed.tzinfo is not None

    def test_a_junk_timestamp_is_not_guessed_at(self):
        assert runner._parse_trivy_timestamp("soon") is None
        assert runner._parse_trivy_timestamp(None) is None
        assert runner._parse_trivy_timestamp(12345) is None


class TestTrivyRunAssessment:
    """What #229 actually reported: `Results` present, `Vulnerabilities`
    empty, exit 0. The finding count alone cannot distinguish that from a
    clean repo, so the verdict rests on the database behind the run."""

    def test_zero_vulnerabilities_against_a_verified_database_is_clean(self, tmp_path):
        cache = _write_trivy_db(tmp_path / "cache")
        repo = tmp_path / "repo"
        repo.mkdir()
        run = _ctx(trivy_cache=cache)
        run.db_fingerprint = runner._trivy_db_fingerprint(cache)
        raw = {"Results": [{"Target": "package-lock.json", "Vulnerabilities": []}]}
        runner._assess_trivy_run(repo, raw, run)
        assert run.health.healthy is True

    def test_zero_vulnerabilities_against_a_broken_database_is_suspect(self, tmp_path):
        """The reported failure, in its reported shape. trivy resolved the
        manifest and said nothing was wrong with it, but the database it
        consulted was not one that could have answered the question."""
        cache = _write_trivy_db(tmp_path / "cache", size=4096)
        repo = tmp_path / "repo"
        repo.mkdir()
        run = _ctx(trivy_cache=cache)
        raw = {"Results": [{"Target": "package-lock.json", "Vulnerabilities": []}]}
        runner._assess_trivy_run(repo, raw, run)
        assert run.health.healthy is False
        assert "not usable" in run.health.summary()

    def test_a_database_that_changed_mid_scan_is_suspect(self, tmp_path):
        """The literal race. Nothing should be able to rewrite a private
        cache any more, but "should" is what #229 was built on."""
        cache = _write_trivy_db(tmp_path / "cache")
        repo = tmp_path / "repo"
        repo.mkdir()
        run = _ctx(trivy_cache=cache)
        run.db_fingerprint = runner._trivy_db_fingerprint(cache)
        # Someone replaces the DB while the scan is running.
        _write_trivy_db(tmp_path / "cache", size=runner.MIN_TRIVY_DB_BYTES + 4096)
        runner._assess_trivy_run(repo, {"Results": [{"Vulnerabilities": []}]}, run)
        assert run.health.healthy is False
        assert "mid-replacement" in run.health.summary()

    def test_trivy_license_is_not_judged_on_the_vulnerability_database(self, tmp_path):
        """`--scanners license` never loads the vulnerability DB. Judging it
        on that DB's state would mark every license scan suspect forever, so
        license findings could never clear."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "package-lock.json").write_text("x" * 2048)
        run = _ctx("trivy-license", trivy_cache=tmp_path / "empty-cache")
        runner._assess_trivy_run(repo, {"Results": []}, run)
        assert run.health.healthy is True


class TestLockfileHeuristic:
    """trivy emits one Results entry per package source it resolved. An
    empty Results list from a checkout carrying a real lockfile means it
    resolved nothing at all -- which is not the same statement as "resolved
    your dependencies, none are vulnerable"."""

    def _run_with_verified_db(self, tmp_path):
        cache = _write_trivy_db(tmp_path / "cache")
        run = _ctx(trivy_cache=cache)
        run.db_fingerprint = runner._trivy_db_fingerprint(cache)
        return run

    def test_a_real_lockfile_counts(self, tmp_path):
        (tmp_path / "poetry.lock").write_text("x" * 2048)
        assert runner.has_resolved_lockfile(tmp_path) is True

    def test_the_git_directory_is_ignored(self, tmp_path):
        git = tmp_path / ".git"
        git.mkdir()
        (git / "package-lock.json").write_text("x" * 4096)
        assert runner.has_resolved_lockfile(tmp_path) is False

    def test_a_dockerfile_only_repo_does_not_trip_it(self, tmp_path):
        """MANIFEST_FILENAMES includes Dockerfile because a Dockerfile change
        could move the dependency set; that is a far lower bar than "trivy
        will definitely emit a Results entry". Firing here would leave every
        Dockerfile-only repo permanently unable to mitigate."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\n" * 60)
        assert runner.has_resolved_lockfile(tmp_path) is False

    def test_a_package_json_without_a_lockfile_does_not_trip_it(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"uuid": "8.3.2"}}) * 40)
        assert runner.has_resolved_lockfile(tmp_path) is False

    def test_setup_py_does_not_trip_it(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\n" * 60)
        assert runner.has_resolved_lockfile(tmp_path) is False

    def test_an_empty_lockfile_does_not_trip_it(self, tmp_path):
        """A fresh npm project's lockfile resolves to nothing, and trivy
        emits no Results entry for one that does."""
        (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}')
        assert runner.has_resolved_lockfile(tmp_path) is False

    def test_no_package_sources_against_a_real_lockfile_is_suspect(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "package-lock.json").write_text("x" * 4096)
        run = self._run_with_verified_db(tmp_path)
        runner._assess_trivy_run(repo, {"Results": []}, run)
        assert run.health.healthy is False
        assert "no package sources" in run.health.summary()

    def test_no_package_sources_with_no_lockfile_stays_healthy(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.c").write_text("int main(){}")
        run = self._run_with_verified_db(tmp_path)
        runner._assess_trivy_run(repo, {"Results": []}, run)
        assert run.health.healthy is True


# ---------------------------------------------------------------------------
# Warming and cache isolation (defect 1)
# ---------------------------------------------------------------------------


class TestWarmTrivyDatabase:
    """Per-run caches are deleted when their run ends and nothing writes back
    to them, so without something maintaining a warm copy, --skip-db-update
    is unreachable and six concurrent scans mean six full downloads."""

    def test_an_already_warm_database_is_left_alone(self, monkeypatch):
        _write_trivy_db(runner.trivy_warm_dir())

        def fail(*args, **kwargs):
            pytest.fail("must not re-download an already-warm database")

        monkeypatch.setattr(runner.subprocess, "run", fail)
        warm, detail = _REAL_ENSURE_WARM()
        assert warm is True and detail == "already warm"

    def test_a_cold_cache_is_downloaded_and_published(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            # trivy writes into whatever --cache-dir it was handed.
            _write_trivy_db(Path(cmd[cmd.index("--cache-dir") + 1]))
            return _Proc(0)

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        warm, detail = _REAL_ENSURE_WARM()
        assert warm is True and detail == "downloaded"
        ok, _ = runner.trivy_db_state(runner.trivy_warm_dir())
        assert ok is True

    def test_a_download_that_produces_an_unusable_cache_is_not_published(self, monkeypatch):
        """Publishing it would hand every later scan a verified-looking
        database that is not one -- the failure this whole PR exists to
        prevent, installed permanently."""

        def fake_run(cmd, **kwargs):
            _write_trivy_db(Path(cmd[cmd.index("--cache-dir") + 1]), size=1024)
            return _Proc(0)

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        warm, detail = _REAL_ENSURE_WARM()
        assert warm is False
        assert "not usable" in detail
        assert not runner.trivy_warm_dir().exists()

    def test_a_failed_download_leaves_the_existing_warm_copy_intact(self, monkeypatch):
        _write_trivy_db(runner.trivy_warm_dir(), next_update="2020-01-01T00:00:00Z")
        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: _Proc(1, stderr="FATAL network"))
        warm, detail = _REAL_ENSURE_WARM()
        assert warm is False
        assert "exited 1" in detail
        # Stale, but still there: a failed refresh must not also destroy the
        # only database on the box.
        assert (runner.trivy_warm_dir() / "db" / "trivy.db").exists()

    def test_no_staging_directories_are_left_behind(self, monkeypatch):
        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: _Proc(1))
        _REAL_ENSURE_WARM()
        leftovers = [
            p for p in runner.tool_cache_root().iterdir()
            if p.name.startswith(runner.TRIVY_STAGING_PREFIX)
        ]
        assert leftovers == []


class TestCacheIsolation:
    def test_each_run_gets_its_own_trivy_cache(self):
        """The race in #229 is two trivy processes over one cache directory.
        Two runs must never resolve to the same TRIVY_CACHE_DIR."""
        seen = []
        for _ in range(2):
            with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
                seen.append(run.env["TRIVY_CACHE_DIR"])
        assert seen[0] != seen[1]

    def test_concurrent_runs_do_not_share_a_cache_directory(self):
        """Nested rather than sequential: this is the actual shape of the
        bug, two runs alive at the same moment."""
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as first:
            with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as second:
                assert first.env["TRIVY_CACHE_DIR"] != second.env["TRIVY_CACHE_DIR"]
            # The inner run's teardown must not have removed the outer one's
            # cache, which would be the original race wearing a new hat.
            assert Path(first.env["TRIVY_CACHE_DIR"]).exists()

    def test_the_private_cache_is_removed_afterwards(self):
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            cache_dir = run.cache_dir
            assert cache_dir.exists()
        assert not cache_dir.exists()

    def test_semgrep_gets_a_private_settings_file_but_keeps_the_shared_rule_cache(self):
        """semgrep rewrites its settings file on every run, so that races.
        Its registry rule cache is left shared on purpose: a private empty
        one per run would re-download the whole ruleset every scan, trading
        a race for a guaranteed cost."""
        with runner._isolated_run("semgrep", ScanHealth(tool="semgrep")) as run:
            assert "SEMGREP_SETTINGS_FILE" in run.env
            assert "XDG_CACHE_HOME" not in (set(run.env) - set(os.environ))

    def test_a_tool_with_no_shared_state_needs_no_cache(self):
        with runner._isolated_run("gitleaks", ScanHealth(tool="gitleaks")) as run:
            assert run.cache_dir is None
            assert run.env is None

    def test_a_run_seeds_from_the_warm_copy(self):
        _write_trivy_db(runner.trivy_warm_dir())
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            assert run.seeded is True
            ok, _ = runner.trivy_db_state(Path(run.env["TRIVY_CACHE_DIR"]))
            assert ok is True

    def test_seeding_does_not_disturb_the_warm_copy(self):
        warm = _write_trivy_db(runner.trivy_warm_dir())
        before = (warm / "db" / "trivy.db").stat().st_size
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")):
            pass
        assert (warm / "db" / "trivy.db").stat().st_size == before

    def test_seeding_hardlinks_rather_than_copying(self):
        """Only safe because the warm directory is replaced whole and never
        written in place; that is what makes a link into it a snapshot."""
        warm = _write_trivy_db(runner.trivy_warm_dir())
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            private = Path(run.env["TRIVY_CACHE_DIR"]) / "db" / "trivy.db"
            assert os.stat(private).st_ino == os.stat(warm / "db" / "trivy.db").st_ino

    def test_a_cold_warm_dir_leaves_the_run_unseeded(self):
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            assert run.seeded is False

    def test_an_unusable_warm_copy_does_not_count_as_seeded(self):
        """A truncated warm DB must not earn --skip-db-update; that would be
        a scan against no usable database, reported as a completed run."""
        _write_trivy_db(runner.trivy_warm_dir(), size=2048)
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            assert run.seeded is False

    def test_a_seeded_run_tells_trivy_not_to_update_the_database(self):
        """--skip-db-update is what takes the scan process out of the race
        entirely: it can no longer be the thing rewriting a DB another scan
        is reading."""
        run = _ctx(seeded=True)
        cmd = runner._isolation_flags("trivy", ["trivy", "fs", "--format", "json", "/repo"], run)
        assert "--skip-db-update" in cmd
        assert cmd[:2] == ["trivy", "fs"]
        assert cmd[-1] == "/repo"

    def test_an_unseeded_run_must_be_allowed_to_download(self):
        """trivy refuses to scan with no database at all, so skipping the
        update on a cold cache would turn every first scan into a failure."""
        run = _ctx(seeded=False)
        assert "--skip-db-update" not in runner._isolation_flags("trivy", ["trivy", "fs", "/repo"], run)

    def test_other_tools_get_no_trivy_flags(self):
        run = _ctx("semgrep", seeded=True)
        cmd = runner._isolation_flags("semgrep", ["semgrep", "scan", "/repo"], run)
        assert cmd == ["semgrep", "scan", "/repo"]

    def test_the_isolated_cache_reaches_the_subprocess(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env")
            return _Proc(0, stdout="{}")

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        runner.run_tool_checked("trivy", tmp_path)
        assert captured["env"]["TRIVY_CACHE_DIR"].startswith(str(runner.tool_cache_root()))

    def test_stale_run_caches_are_swept(self):
        """A worker killed by SIGKILL or the OOM killer never reaches the
        cleanup in the finally block, and task_acks_late makes that an
        expected path rather than a rare one."""
        root = runner._run_cache_root()
        root.mkdir(parents=True, exist_ok=True)
        stale = root / "trivy-ancient"
        stale.mkdir()
        old = datetime.now(timezone.utc).timestamp() - runner.RUN_CACHE_MAX_AGE_SECONDS - 60
        os.utime(stale, (old, old))
        fresh = root / "trivy-current"
        fresh.mkdir()

        assert runner.sweep_stale_run_caches() == 1
        assert not stale.exists()
        assert fresh.exists()

    def test_every_isolated_tool_is_a_real_tool(self):
        """A typo here would silently disable isolation for the tool it was
        meant to protect."""
        assert set(runner.TOOL_CACHE_ISOLATION) <= set(runner.TOOL_COMMANDS)


class TestRunToolChecked:
    def test_it_returns_the_report_and_a_verdict(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            runner.subprocess, "run",
            lambda *a, **k: _Proc(0, stdout=json.dumps({"Results": [{"Vulnerabilities": []}]})),
        )
        raw, health = runner.run_tool_checked("trivy", tmp_path)
        assert raw == {"Results": [{"Vulnerabilities": []}]}
        assert isinstance(health, ScanHealth)

    def test_run_tool_still_returns_only_the_report(self, monkeypatch, tmp_path):
        """Existing callers (PR Guardrail, the snippet scanner) keep the old
        signature; only the paths that *mitigate* need the verdict."""
        monkeypatch.setattr(
            runner.subprocess, "run", lambda *a, **k: _Proc(0, stdout=json.dumps({"Results": []}))
        )
        assert runner.run_tool("trivy", tmp_path) == {"Results": []}

    def test_a_stderr_warning_reaches_the_verdict(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            runner.subprocess, "run",
            lambda *a, **k: _Proc(
                0,
                stdout=json.dumps({"Results": [{"Vulnerabilities": []}]}),
                stderr="WARN unable to open the database, falling back",
            ),
        )
        _, health = runner.run_tool_checked("trivy", tmp_path)
        assert health.healthy is False

    def test_an_empty_report_is_not_a_clean_result(self, monkeypatch, tmp_path):
        """The return value keeps its shape (parsers downstream expect one)
        but the verdict records that there was nothing to read. 'Nothing' has
        been read as 'clean' twice in this file's history already."""
        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: _Proc(0, stdout=""))
        raw, health = runner.run_tool_checked("trivy", tmp_path)
        assert raw == {}
        assert health.healthy is False
        assert "wrote no report" in health.summary()

    def test_unparseable_output_is_not_a_clean_result(self, monkeypatch, tmp_path):
        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: _Proc(0, stdout="<html>oops"))
        raw, health = runner.run_tool_checked("trivy", tmp_path)
        assert raw == {}
        assert health.healthy is False
        assert "not valid JSON" in health.summary()

    def test_an_unsupported_tool_still_raises(self, tmp_path):
        with pytest.raises(ValueError):
            runner.run_tool_checked("not-a-tool", tmp_path)

    def test_execute_requires_a_run_context(self, tmp_path):
        """The context is a parameter rather than ambient state on purpose:
        a caller that forgets it fails here, loudly, instead of silently
        scanning against a shared cache and recording no health."""
        with pytest.raises(TypeError):
            runner._execute("trivy", ["trivy", "fs", str(tmp_path)], tmp_path)


class TestToolsThatBypassExecute:
    """gitleaks, noseyparker and modelscan return before _execute's stderr
    check, so they need their own -- otherwise the three tools most likely
    to be reporting on secrets get no health signal at all."""

    def test_gitleaks_warnings_reach_the_verdict(self, monkeypatch, tmp_path):
        def fake_run(cmd, **kwargs):
            report = cmd[cmd.index("--report-path") + 1]
            Path(report).write_text("[]")
            return _Proc(0, stderr="WRN failed to download rule set")

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        _, health = runner.run_tool_checked("gitleaks", tmp_path)
        assert health.healthy is False

    def test_modelscan_warnings_reach_the_verdict(self, monkeypatch, tmp_path):
        def fake_run(cmd, **kwargs):
            report = cmd[cmd.index("-o") + 1]
            Path(report).write_text(json.dumps({"summary": {"total_issues": 0}, "issues": []}))
            return _Proc(0, stderr="failed to initialize scanner plugins")

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        _, health = runner.run_tool_checked("modelscan", tmp_path)
        assert health.healthy is False


class TestNuclei:
    def test_a_broken_run_raises_instead_of_reporting_nothing(self, monkeypatch):
        """run_nuclei bypasses _execute, so it bypassed the exit-code check
        every other tool got. A broken run returned [], which api_scan_tasks
        ingested as a completed, healthy, zero-finding scan -- mitigating
        every open api-scan finding on the target."""
        monkeypatch.setattr(
            runner.subprocess, "run", lambda *a, **k: _Proc(1, stderr="FTL could not resolve host")
        )
        with pytest.raises(runner.ToolExecutionError) as ei:
            runner.run_nuclei(["https://api.example.com/health"])
        assert "exited 1" in str(ei.value)

    def test_the_update_check_is_disabled_when_templates_exist(self, monkeypatch):
        """nuclei rewrites its shared template store in place when it decides
        an update is due; two concurrent runs then have one replacing what
        the other is loading."""
        captured = {}
        monkeypatch.setattr(runner, "nuclei_templates_present", lambda: True)
        monkeypatch.setattr(
            runner.subprocess, "run",
            lambda cmd, **k: (captured.update(cmd=cmd), _Proc(0))[1],
        )
        runner.run_nuclei(["https://api.example.com/health"])
        assert "-duc" in captured["cmd"]

    def test_the_update_check_is_left_on_when_there_are_no_templates(self, monkeypatch):
        """nuclei's fresh-install path sits behind the same update check, so
        -duc on a host with no templates leaves it with nothing to scan
        with: exit 0 and zero findings from a scanner that loaded no checks
        at all."""
        captured = {}
        monkeypatch.setattr(runner, "nuclei_templates_present", lambda: False)
        monkeypatch.setattr(
            runner.subprocess, "run",
            lambda cmd, **k: (captured.update(cmd=cmd), _Proc(0))[1],
        )
        runner.run_nuclei(["https://api.example.com/health"])
        assert "-duc" not in captured["cmd"]

    def test_an_empty_template_directory_does_not_count_as_present(self, tmp_path, monkeypatch):
        """Absent, present-but-empty, and populated are three distinct answers.

        Driven through $HOME rather than an override, because $HOME is the
        only thing nuclei itself consults -- run_nuclei passes it no
        template-directory flag. A test that pointed this function at some
        other directory would be asserting agreement with a location nuclei
        never opens.
        """
        monkeypatch.setattr(runner.Path, "home", classmethod(lambda cls: tmp_path))
        templates = tmp_path / "nuclei-templates"

        assert runner.nuclei_templates_present() is False
        templates.mkdir()
        assert runner.nuclei_templates_present() is False
        (templates / "cve.yaml").write_text("id: x")
        assert runner.nuclei_templates_present() is True

    def test_the_template_store_is_not_redirectable_by_environment(self, tmp_path, monkeypatch):
        """The removed NUCLEI_TEMPLATES_DIR knob must not come back.

        It could only ever create the false positive nuclei_templates_present
        exists to avoid: a directory this process can see, nuclei cannot, and
        `-duc` passed to a scanner with no checks loaded. Pinned as a test
        because the next person to want a configurable path will find the
        idea reasonable.
        """
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "cve.yaml").write_text("id: x")

        empty_home = tmp_path / "home"
        empty_home.mkdir()
        monkeypatch.setattr(runner.Path, "home", classmethod(lambda cls: empty_home))
        monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(elsewhere))

        assert runner.nuclei_templates_present() is False


# ---------------------------------------------------------------------------
# Ingestion gating (defect 2, the one that actually cleared the findings)
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _target(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)
        workspace = Workspace(organization_id=org.id, name="WS", api_key="key-229")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)
        target = Target(name="rikugan", repo_url="https://github.com/geekshiv/rikugan", workspace_id=workspace.id)
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _parsed(rule_id: str) -> dict:
    return {
        "rule_id": rule_id,
        "title": rule_id,
        "description": "",
        "file_path": "package-lock.json",
        "line_start": None,
        "line_end": None,
        "severity": Severity.HIGH,
        "snippet": "",
        "cve_id": None,
    }


def _existing_finding(engine, target_id: int, rule_id: str = "CVE-2026-41907") -> int:
    """A live, previously-found vulnerability sitting Open, exactly like the
    five that #229 cleared."""
    with Session(engine) as session:
        finding = Finding(
            target_id=target_id,
            dedup_hash=compute_dedup_hash(rule_id=rule_id, file_path="package-lock.json", tool="trivy", snippet=""),
            tool="trivy",
            rule_id=rule_id,
            title=rule_id,
            file_path="package-lock.json",
            severity=Severity.HIGH,
            branch="main",
            state=FindingState.OPEN,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _ingest(engine, target_id, parsed, health):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = Scan(target_id=target_id, tool="trivy", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_findings(session, target, scan, "trivy", "main", parsed, health=health)
        session.refresh(scan)
        return scan.id


def _state(engine, finding_id) -> FindingState:
    with Session(engine) as session:
        return session.get(Finding, finding_id).state


def _scan(engine, scan_id) -> Scan:
    with Session(engine) as session:
        return session.get(Scan, scan_id)


class TestSuspectRunsDoNotMitigate:
    def test_a_suspect_zero_finding_run_leaves_live_findings_open(self, engine):
        """The regression this issue is about. Five real, still-present
        vulnerabilities were marked Mitigated because one racing trivy
        process came back empty."""
        target_id = _target(engine)
        finding_id = _existing_finding(engine, target_id)

        health = ScanHealth(tool="trivy")
        health.degrade("trivy ran without a vulnerability database")
        _ingest(engine, target_id, [], health)

        assert _state(engine, finding_id) == FindingState.OPEN

    def test_a_suspect_run_that_did_find_something_still_mitigates_nothing(self, engine):
        """A trivy process that saw two of five CVEs would otherwise mitigate
        the other three: the same failure with a smaller blast radius, not a
        different one."""
        target_id = _target(engine)
        stale_id = _existing_finding(engine, target_id, rule_id="CVE-2026-34043")

        health = ScanHealth(tool="trivy")
        health.degrade("results may be incomplete")
        _ingest(engine, target_id, [_parsed("GHSA-5c6j-r48x-rmvq")], health)

        assert _state(engine, stale_id) == FindingState.OPEN

    def test_the_scan_row_records_the_verdict_and_what_was_done(self, engine):
        """"Completed, 0 findings" with nothing beside it is the false
        all-clear; the row has to carry the caveat for any surface to show
        it."""
        target_id = _target(engine)
        _existing_finding(engine, target_id)

        health = ScanHealth(tool="trivy")
        health.degrade("trivy reported no package sources at all")
        scan_id = _ingest(engine, target_id, [], health)

        scan = _scan(engine, scan_id)
        assert scan.status == "completed"
        assert scan.health == SUSPECT
        assert "no package sources" in scan.health_note
        assert "left open rather than mitigated" in scan.health_note


class TestHealthyRunsStillMitigate:
    def test_a_healthy_zero_finding_run_mitigates(self, engine):
        """The legitimate case must keep working. A genuinely clean rescan is
        how a fixed vulnerability leaves the inventory, and breaking it would
        just be a different way of lying about the repo."""
        target_id = _target(engine)
        finding_id = _existing_finding(engine, target_id)

        _ingest(engine, target_id, [], ScanHealth(tool="trivy"))

        assert _state(engine, finding_id) == FindingState.MITIGATED

    def test_a_healthy_run_records_itself_as_healthy(self, engine):
        target_id = _target(engine)
        scan_id = _ingest(engine, target_id, [], ScanHealth(tool="trivy"))
        scan = _scan(engine, scan_id)
        assert scan.health == HEALTHY
        assert scan.health_note == ""

    def test_a_healthy_run_still_mitigates_only_what_it_did_not_see(self, engine):
        target_id = _target(engine)
        kept_id = _existing_finding(engine, target_id, rule_id="CVE-2026-41907")
        gone_id = _existing_finding(engine, target_id, rule_id="CVE-2026-34043")

        _ingest(engine, target_id, [_parsed("CVE-2026-41907")], ScanHealth(tool="trivy"))

        assert _state(engine, kept_id) == FindingState.OPEN
        assert _state(engine, gone_id) == FindingState.MITIGATED

    def test_a_healthy_run_reopens_a_finding_that_came_back(self, engine):
        """The other half of the #229 report: the solo rescan found all five
        again and they returned as Reopened."""
        target_id = _target(engine)
        finding_id = _existing_finding(engine, target_id)
        _ingest(engine, target_id, [], ScanHealth(tool="trivy"))
        assert _state(engine, finding_id) == FindingState.MITIGATED

        _ingest(engine, target_id, [_parsed("CVE-2026-41907")], ScanHealth(tool="trivy"))
        assert _state(engine, finding_id) == FindingState.REOPENED


class TestNoHealthSignalAtAll:
    """The CI/CD push path has no scanner of ours behind it, so it often
    offers no evidence either way. "Unknown" is deliberately not a synonym
    for "healthy"."""

    def test_an_unexplained_zero_finding_run_mitigates_nothing(self, engine):
        target_id = _target(engine)
        finding_id = _existing_finding(engine, target_id)

        scan_id = _ingest(engine, target_id, [], None)

        assert _state(engine, finding_id) == FindingState.OPEN
        assert _scan(engine, scan_id).health == UNKNOWN

    def test_a_run_that_reported_findings_demonstrably_ran(self, engine):
        """Backwards compatibility for the push endpoint: a result set that
        contains findings is its own proof the tool executed."""
        target_id = _target(engine)
        stale_id = _existing_finding(engine, target_id, rule_id="CVE-2026-34043")

        _ingest(engine, target_id, [_parsed("CVE-2026-41907")], None)

        assert _state(engine, stale_id) == FindingState.MITIGATED


class TestSarifHealth:
    def test_a_successful_invocation_is_healthy(self):
        payload = {"runs": [{"tool": {"driver": {"name": "codeql"}}, "invocations": [{"executionSuccessful": True}]}]}
        health = sarif_health(payload, "sarif")
        assert health is not None and health.healthy is True

    def test_a_failed_invocation_is_suspect(self):
        """An empty results array from a CI job that broke is not a clean
        repository, and SARIF says so directly."""
        payload = {"runs": [{"tool": {"driver": {"name": "codeql"}}, "invocations": [{"executionSuccessful": False}]}]}
        health = sarif_health(payload, "sarif")
        assert health is not None and health.healthy is False
        assert "codeql" in health.summary()

    def test_absent_invocations_are_unknown_not_healthy(self):
        """`invocations` is optional in the SARIF spec and omitted by several
        producers this platform expects (trivy and gitleaks among them).
        Calling that "healthy" would be unknown rendering as clean, and would
        make the not-authoritative branch unreachable for most real push
        traffic."""
        assert sarif_health({"runs": [{"results": []}]}, "sarif") is None
        assert sarif_health({}, "sarif") is None

    def test_an_invocation_that_omits_the_field_asserts_nothing(self):
        payload = {"runs": [{"invocations": [{"startTimeUtc": "2026-01-01T00:00:00Z"}]}]}
        assert sarif_health(payload, "sarif") is None

    def test_malformed_runs_do_not_explode(self):
        assert sarif_health({"runs": ["nonsense", None]}, "sarif") is None


def test_findings_left_open_are_not_lost(engine):
    """A refused mitigation is not silent data loss: the next healthy run of
    the same tool mitigates them normally if they really are gone."""
    target_id = _target(engine)
    finding_id = _existing_finding(engine, target_id)

    suspect = ScanHealth(tool="trivy")
    suspect.degrade("database missing")
    _ingest(engine, target_id, [], suspect)
    assert _state(engine, finding_id) == FindingState.OPEN

    _ingest(engine, target_id, [], ScanHealth(tool="trivy"))
    assert _state(engine, finding_id) == FindingState.MITIGATED


def test_open_findings_of_other_tools_are_untouched(engine):
    """Scoping regression guard: the mitigation query is per-tool, and the
    new gate must not widen or narrow it."""
    target_id = _target(engine)
    with Session(engine) as session:
        other = Finding(
            target_id=target_id,
            dedup_hash="semgrep-hash",
            tool="semgrep",
            rule_id="python.lang.security",
            title="x",
            file_path="app.py",
            severity=Severity.MEDIUM,
            branch="main",
            state=FindingState.OPEN,
        )
        session.add(other)
        session.commit()
        session.refresh(other)
        other_id = other.id

    _ingest(engine, target_id, [], ScanHealth(tool="trivy"))

    with Session(engine) as session:
        assert session.get(Finding, other_id).state == FindingState.OPEN
        assert session.exec(select(Finding).where(Finding.tool == "trivy")).all() == []


# ---------------------------------------------------------------------------
# The wiring between them
# ---------------------------------------------------------------------------


def test_run_scan_passes_the_health_verdict_into_ingestion(engine, monkeypatch):
    """The two halves of this fix are only worth anything joined up. A
    runner that produces a verdict and a task that drops it on the floor
    would pass every other test in this file and still mitigate five live
    CVEs."""
    from app.tasks import scan_tasks

    target_id = _target(engine)
    with Session(engine) as session:
        scan = Scan(target_id=target_id, tool="trivy", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    suspect = ScanHealth(tool="trivy")
    suspect.degrade("trivy's vulnerability database was not usable for this run")
    captured = {}

    monkeypatch.setattr(scan_tasks, "engine", engine)
    monkeypatch.setattr(scan_tasks.runner, "clone_repo", lambda *a, **k: Path("/tmp"))
    monkeypatch.setattr(scan_tasks, "refresh_ai_repo_status", lambda *a, **k: None)
    monkeypatch.setattr(scan_tasks.runner, "ensure_warm_trivy_db", lambda *a, **k: (True, "already warm"))
    monkeypatch.setattr(scan_tasks.runner, "run_tool_checked", lambda tool, repo_path: ({}, suspect))
    monkeypatch.setattr(scan_tasks.runner, "normalize_file_path", lambda file_path, repo_path: file_path)

    def fake_ingest(session, target, scan, tool, branch, parsed, health=None):
        captured["health"] = health
        return 0

    monkeypatch.setattr(scan_tasks, "ingest_findings", fake_ingest)

    result = scan_tasks.run_scan.apply(
        kwargs={"target_id": target_id, "tool": "trivy", "scan_id": scan_id}
    ).get()

    assert captured["health"] is suspect
    assert result["health"] == SUSPECT


def test_run_scan_warms_the_database_before_scanning(engine, monkeypatch):
    """The fan-out interlock: without this, six scans dispatched together
    either race a shared cache or download the database six times."""
    from app.tasks import scan_tasks

    target_id = _target(engine)
    with Session(engine) as session:
        scan = Scan(target_id=target_id, tool="trivy", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    order = []
    monkeypatch.setattr(scan_tasks, "engine", engine)
    monkeypatch.setattr(scan_tasks.runner, "clone_repo", lambda *a, **k: Path("/tmp"))
    monkeypatch.setattr(scan_tasks, "refresh_ai_repo_status", lambda *a, **k: None)
    monkeypatch.setattr(
        scan_tasks.runner, "ensure_warm_trivy_db",
        lambda *a, **k: (order.append("warm"), (True, "downloaded"))[1],
    )
    monkeypatch.setattr(
        scan_tasks.runner, "run_tool_checked",
        lambda tool, repo_path: (order.append("scan"), ({}, ScanHealth(tool=tool)))[1],
    )
    monkeypatch.setattr(scan_tasks.runner, "normalize_file_path", lambda file_path, repo_path: file_path)
    monkeypatch.setattr(scan_tasks, "ingest_findings", lambda *a, **k: 0)

    scan_tasks.run_scan.apply(
        kwargs={"target_id": target_id, "tool": "trivy", "scan_id": scan_id}
    ).get()

    assert order == ["warm", "scan"]


def test_run_scan_does_not_warm_for_tools_that_need_no_database(engine, monkeypatch):
    from app.tasks import scan_tasks

    target_id = _target(engine)
    with Session(engine) as session:
        scan = Scan(target_id=target_id, tool="gitleaks", branch="main", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id

    monkeypatch.setattr(scan_tasks, "engine", engine)
    monkeypatch.setattr(scan_tasks.runner, "clone_repo", lambda *a, **k: Path("/tmp"))
    monkeypatch.setattr(scan_tasks, "refresh_ai_repo_status", lambda *a, **k: None)
    monkeypatch.setattr(
        scan_tasks.runner, "ensure_warm_trivy_db",
        lambda *a, **k: pytest.fail("gitleaks has no vulnerability database to warm"),
    )
    monkeypatch.setattr(scan_tasks.runner, "run_tool_checked", lambda tool, repo_path: ([], ScanHealth(tool=tool)))
    monkeypatch.setattr(scan_tasks.runner, "normalize_file_path", lambda file_path, repo_path: file_path)
    monkeypatch.setattr(scan_tasks, "ingest_findings", lambda *a, **k: 0)

    scan_tasks.run_scan.apply(
        kwargs={"target_id": target_id, "tool": "gitleaks", "scan_id": scan_id}
    ).get()
