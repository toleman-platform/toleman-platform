"""Concurrent scans must not produce a false all-clear (#229).

The reproduction: six scans dispatched together, all running trivy against
one shared vulnerability-DB cache. One of them read the DB while another was
replacing it and came back with exit code 0, valid JSON and an empty
``Vulnerabilities`` array for a repository with five live High/Medium CVEs.
``ingest_findings`` could not tell that apart from "scanned it, it's clean",
so it marked all five ``Mitigated``. The same scan run alone four minutes
later found all five and reopened them.

Two defects, and this file covers both:

  1. Concurrent same-tool runs racing shared mutable tool state. Each run now
     gets its own trivy/semgrep cache directory, seeded from the shared one,
     and trivy runs with --skip-db-update so no scan process can be the thing
     rewriting a DB another scan is reading.

  2. The more important one: a zero-finding result being trusted
     unconditionally. The runner now surfaces a ScanHealth verdict, and
     ingest_findings will not mitigate on a run that is not positively
     healthy. This mirrors app/core/osv_malware.py, which returns None on a
     failed check and {} on a completed-and-clean one precisely so an outage
     cannot read as an all-clear.

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
        runner._note_stderr("trivy", "INFO Vulnerability scanning is enabled\nINFO Number of language-specific files: 3", health)
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


class TestTrivyDatabaseFreshness:
    """The signal that speaks directly to #229's reproduction: a trivy run
    with no usable vulnerability database behind it cannot support the claim
    that a repository is clean."""

    def _write_metadata(self, cache_dir: Path, next_update: str | None) -> None:
        db = cache_dir / "db"
        db.mkdir(parents=True, exist_ok=True)
        payload = {"Version": 2, "UpdatedAt": "2026-08-22T00:00:00Z"}
        if next_update is not None:
            payload["NextUpdate"] = next_update
        (db / "metadata.json").write_text(json.dumps(payload))

    def test_a_fresh_database_is_healthy(self, tmp_path):
        next_update = (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat().replace("+00:00", "Z")
        self._write_metadata(tmp_path, next_update)
        health = ScanHealth(tool="trivy")
        runner._assess_trivy_db(tmp_path, health)
        assert health.healthy is True

    def test_no_database_at_all_is_suspect(self, tmp_path):
        """Zero findings from a scanner with no vulnerability data is not a
        clean repository; it is a scanner that could not have found one."""
        health = ScanHealth(tool="trivy")
        runner._assess_trivy_db(tmp_path, health)
        assert health.healthy is False
        assert "database" in health.summary()

    def test_unreadable_metadata_is_suspect(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir(parents=True)
        (db / "metadata.json").write_text("{not json")
        health = ScanHealth(tool="trivy")
        runner._assess_trivy_db(tmp_path, health)
        assert health.healthy is False

    def test_metadata_with_no_next_update_is_suspect(self, tmp_path):
        self._write_metadata(tmp_path, None)
        health = ScanHealth(tool="trivy")
        runner._assess_trivy_db(tmp_path, health)
        assert health.healthy is False

    def test_a_database_long_past_its_refresh_deadline_is_suspect(self, tmp_path):
        stale = datetime.now(timezone.utc) - timedelta(hours=runner.TRIVY_DB_STALE_GRACE_HOURS + 48)
        self._write_metadata(tmp_path, stale.isoformat().replace("+00:00", "Z"))
        health = ScanHealth(tool="trivy")
        runner._assess_trivy_db(tmp_path, health)
        assert health.healthy is False
        assert "refresh deadline" in health.summary()

    def test_a_database_just_past_its_deadline_is_still_healthy(self, tmp_path):
        """NextUpdate passing is routine -- trivy publishes every few hours
        and refreshes opportunistically. Only a refresh that has been failing
        for days says anything about the result."""
        recent = datetime.now(timezone.utc) - timedelta(hours=2)
        self._write_metadata(tmp_path, recent.isoformat().replace("+00:00", "Z"))
        health = ScanHealth(tool="trivy")
        runner._assess_trivy_db(tmp_path, health)
        assert health.healthy is True

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


class TestZeroFindingsAgainstANonEmptyManifest:
    """trivy emits one Results entry per package source it resolved,
    regardless of whether anything in it was vulnerable. So an empty Results
    list for a repo that demonstrably has manifests means trivy resolved
    nothing at all -- a different statement from "resolved your dependencies,
    none are vulnerable", and only the second one may clear findings."""

    def _repo_with_manifest(self, tmp_path: Path) -> Path:
        (tmp_path / "package.json").write_text('{"dependencies": {"uuid": "8.3.2"}}')
        return tmp_path

    def test_manifest_detection_finds_a_lockfile(self, tmp_path):
        (tmp_path / "poetry.lock").write_text("")
        assert runner.repo_has_dependency_manifest(tmp_path) is True

    def test_manifest_detection_ignores_the_git_directory(self, tmp_path):
        """A packfile is not a manifest, and walking one is wasted work."""
        git = tmp_path / ".git"
        git.mkdir()
        (git / "package.json").write_text("{}")
        assert runner.repo_has_dependency_manifest(tmp_path) is False

    def test_a_repo_with_no_manifest_is_not_a_signal(self, tmp_path):
        (tmp_path / "README.md").write_text("hi")
        assert runner.repo_has_dependency_manifest(tmp_path) is False

    def test_empty_results_against_a_manifest_is_suspect(self, tmp_path):
        repo = self._repo_with_manifest(tmp_path)
        run = runner._RunContext(health=ScanHealth(tool="trivy"))
        runner._assess_result("trivy", repo, {"Results": []}, run)
        assert run.health.healthy is False
        assert "dependency manifests" in run.health.summary()

    def test_resolved_results_with_no_vulnerabilities_stays_healthy(self, tmp_path):
        """The legitimate clean case has to keep working, or the fix is just
        a different way of being wrong."""
        repo = self._repo_with_manifest(tmp_path)
        run = runner._RunContext(health=ScanHealth(tool="trivy"))
        runner._assess_result(
            "trivy", repo, {"Results": [{"Target": "package-lock.json", "Vulnerabilities": []}]}, run
        )
        assert run.health.healthy is True

    def test_empty_results_with_no_manifest_stays_healthy(self, tmp_path):
        (tmp_path / "main.c").write_text("int main(){}")
        run = runner._RunContext(health=ScanHealth(tool="trivy"))
        runner._assess_result("trivy", tmp_path, {"Results": []}, run)
        assert run.health.healthy is True


# ---------------------------------------------------------------------------
# Cache isolation (defect 1)
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_workdir(tmp_path, monkeypatch):
    """Keep every cache this module creates inside tmp_path, and keep the
    seeding step away from whatever trivy/semgrep cache the machine running
    the tests happens to have."""
    monkeypatch.setattr(runner.settings, "scan_workdir", str(tmp_path / "scans"))
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "shared-trivy"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "shared-xdg"))
    return tmp_path


class TestCacheIsolation:
    def test_each_run_gets_its_own_trivy_cache(self, isolated_workdir):
        """The race in #229 is two trivy processes over one cache directory.
        Two runs must never resolve to the same TRIVY_CACHE_DIR."""
        seen = []
        for _ in range(2):
            with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
                seen.append(run.env["TRIVY_CACHE_DIR"])
        assert seen[0] != seen[1]

    def test_concurrent_runs_do_not_share_a_cache_directory(self, isolated_workdir):
        """Nested rather than sequential: this is the actual shape of the bug,
        two runs alive at the same moment."""
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as first:
            with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as second:
                assert first.env["TRIVY_CACHE_DIR"] != second.env["TRIVY_CACHE_DIR"]
                assert first.cache_dir != second.cache_dir
            # The inner run's teardown must not have removed the outer one's
            # cache, which would be the original race wearing a new hat.
            assert Path(first.env["TRIVY_CACHE_DIR"]).exists()

    def test_the_private_cache_is_removed_afterwards(self, isolated_workdir):
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            cache_dir = run.cache_dir
            assert cache_dir.exists()
        assert not cache_dir.exists()

    def test_the_context_is_cleared_afterwards(self, isolated_workdir):
        with runner._isolated_run("trivy", ScanHealth(tool="trivy")):
            assert runner._CURRENT_RUN.get() is not None
        assert runner._CURRENT_RUN.get() is None

    def test_semgrep_gets_its_own_rule_cache_and_settings_file(self, isolated_workdir):
        """--config=auto downloads the registry ruleset and semgrep rewrites
        its settings file on every run; concurrent runs race both."""
        with runner._isolated_run("semgrep", ScanHealth(tool="semgrep")) as run:
            assert run.env["XDG_CACHE_HOME"] != str(isolated_workdir / "shared-xdg")
            assert run.env["SEMGREP_SETTINGS_FILE"].startswith(run.env["XDG_CACHE_HOME"])

    def test_a_tool_with_no_shared_state_needs_no_cache(self, isolated_workdir):
        with runner._isolated_run("gitleaks", ScanHealth(tool="gitleaks")) as run:
            assert run.cache_dir is None
            assert run.env == {}

    def test_the_shared_cache_is_seeded_not_moved(self, isolated_workdir):
        shared_db = isolated_workdir / "shared-trivy" / "db"
        shared_db.mkdir(parents=True)
        (shared_db / "trivy.db").write_bytes(b"pretend database")
        (shared_db / "metadata.json").write_text(json.dumps({"NextUpdate": "2026-12-01T00:00:00Z"}))

        with runner._isolated_run("trivy", ScanHealth(tool="trivy")) as run:
            private_db = Path(run.env["TRIVY_CACHE_DIR"]) / "db"
            assert run.seeded is True
            assert (private_db / "trivy.db").read_bytes() == b"pretend database"

        # The shared copy is the source of truth for every future run and must
        # survive this one's teardown untouched.
        assert (shared_db / "trivy.db").read_bytes() == b"pretend database"

    def test_a_seeded_run_tells_trivy_not_to_update_the_database(self, isolated_workdir):
        """--skip-db-update is what takes the scan process out of the race
        entirely: it can no longer be the thing rewriting a DB another scan
        is reading."""
        run = runner._RunContext(health=ScanHealth(tool="trivy"), seeded=True)
        cmd = runner._isolation_flags("trivy", ["trivy", "fs", "--format", "json", "/repo"], run)
        assert "--skip-db-update" in cmd
        assert cmd[:2] == ["trivy", "fs"]
        assert cmd[-1] == "/repo"

    def test_an_unseeded_run_must_be_allowed_to_download(self, isolated_workdir):
        """trivy refuses to scan with no database at all, so skipping the
        update on a cold cache would turn every first scan into a failure."""
        run = runner._RunContext(health=ScanHealth(tool="trivy"), seeded=False)
        cmd = runner._isolation_flags("trivy", ["trivy", "fs", "/repo"], run)
        assert "--skip-db-update" not in cmd

    def test_other_tools_get_no_trivy_flags(self, isolated_workdir):
        run = runner._RunContext(health=ScanHealth(tool="semgrep"), seeded=True)
        cmd = runner._isolation_flags("semgrep", ["semgrep", "scan", "/repo"], run)
        assert cmd == ["semgrep", "scan", "/repo"]

    def test_the_isolated_cache_reaches_the_subprocess(self, isolated_workdir, monkeypatch):
        captured = {}

        class P:
            returncode, stdout, stderr = 0, "{}", ""

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env")
            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        runner.run_tool_checked("trivy", isolated_workdir)
        assert captured["env"]["TRIVY_CACHE_DIR"] != str(isolated_workdir / "shared-trivy")

    def test_nuclei_never_rewrites_its_shared_template_store_mid_scan(self, monkeypatch):
        """nuclei's equivalent of the trivy DB: one shared template directory
        it updates in place. A run that loaded a half-written template set
        still exits 0 and simply finds less."""
        captured = {}

        class P:
            returncode, stdout, stderr = 0, "", ""

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        runner.run_nuclei(["https://api.example.com/health"])
        assert "-duc" in captured["cmd"]


class TestRunToolChecked:
    def _fake_proc(self, monkeypatch, returncode=0, stdout="{}", stderr=""):
        class P:
            pass

        p = P()
        p.returncode, p.stdout, p.stderr = returncode, stdout, stderr
        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: p)
        return p

    def test_it_returns_the_report_and_a_verdict(self, isolated_workdir, monkeypatch):
        self._fake_proc(monkeypatch, stdout=json.dumps({"Results": [{"Vulnerabilities": []}]}))
        raw, health = runner.run_tool_checked("trivy", isolated_workdir)
        assert raw == {"Results": [{"Vulnerabilities": []}]}
        assert isinstance(health, ScanHealth)

    def test_run_tool_still_returns_only_the_report(self, isolated_workdir, monkeypatch):
        """Existing callers (PR Guardrail, the snippet scanner) keep the old
        signature; only the paths that *mitigate* need the verdict."""
        self._fake_proc(monkeypatch, stdout=json.dumps({"Results": []}))
        assert runner.run_tool("trivy", isolated_workdir) == {"Results": []}

    def test_a_stderr_warning_reaches_the_verdict(self, isolated_workdir, monkeypatch):
        self._fake_proc(
            monkeypatch,
            stdout=json.dumps({"Results": [{"Vulnerabilities": []}]}),
            stderr="WARN unable to open the database, falling back",
        )
        _, health = runner.run_tool_checked("trivy", isolated_workdir)
        assert health.healthy is False

    def test_an_empty_report_against_a_manifest_is_suspect_end_to_end(self, isolated_workdir, monkeypatch):
        """The whole #229 reproduction in one assertion: exit 0, valid JSON,
        nothing found, against a repo that plainly has dependencies."""
        repo = isolated_workdir / "repo"
        repo.mkdir()
        (repo / "package.json").write_text('{"dependencies": {"uuid": "8.3.2"}}')
        self._fake_proc(monkeypatch, stdout=json.dumps({"Results": []}))
        raw, health = runner.run_tool_checked("trivy", repo)
        assert raw == {"Results": []}
        assert health.healthy is False

    def test_an_unsupported_tool_still_raises(self, isolated_workdir):
        with pytest.raises(ValueError):
            runner.run_tool_checked("not-a-tool", isolated_workdir)

    def test_every_isolated_tool_is_a_real_tool(self):
        """A typo here would silently disable isolation for the tool it was
        meant to protect."""
        assert set(runner.TOOL_CACHE_ISOLATION) <= set(runner.TOOL_COMMANDS)


class TestSeedCache:
    def test_seeding_a_missing_source_is_not_an_error(self, tmp_path):
        """A cold cache is normal (a fresh container, a first scan). The run
        proceeds and simply pays for the download."""
        assert runner._seed_cache(tmp_path / "nope", tmp_path / "dst") is False

    def test_seeding_uses_hardlinks_so_it_costs_no_disk(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "trivy.db").write_bytes(b"x" * 1024)
        dst = tmp_path / "dst"
        assert runner._seed_cache(src, dst) is True
        assert os.stat(src / "trivy.db").st_ino == os.stat(dst / "trivy.db").st_ino

    def test_an_empty_source_directory_does_not_count_as_seeded(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        assert runner._seed_cache(src, tmp_path / "dst") is False


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
        """"Completed · 0 findings" with nothing beside it is the false
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
    """The CI/CD push path has no scanner of ours behind it, so it offers no
    evidence either way. "Unknown" is deliberately not a synonym for
    "healthy"."""

    def test_an_unexplained_zero_finding_run_mitigates_nothing(self, engine):
        target_id = _target(engine)
        finding_id = _existing_finding(engine, target_id)

        _ingest(engine, target_id, [], None)

        assert _state(engine, finding_id) == FindingState.OPEN
        assert _scan(engine, _ingest(engine, target_id, [], None)).health == UNKNOWN

    def test_a_run_that_reported_findings_demonstrably_ran(self, engine):
        """Backwards compatibility for the push endpoint: a result set that
        contains findings is its own proof the tool executed."""
        target_id = _target(engine)
        stale_id = _existing_finding(engine, target_id, rule_id="CVE-2026-34043")

        _ingest(engine, target_id, [_parsed("CVE-2026-41907")], None)

        assert _state(engine, stale_id) == FindingState.MITIGATED


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


# ---------------------------------------------------------------------------
# Pushed SARIF declares its own health
# ---------------------------------------------------------------------------


class TestSarifHealth:
    def test_a_successful_invocation_is_healthy(self):
        payload = {"runs": [{"tool": {"driver": {"name": "codeql"}}, "invocations": [{"executionSuccessful": True}]}]}
        assert sarif_health(payload, "sarif").healthy is True

    def test_a_failed_invocation_is_suspect(self):
        """An empty results array from a CI job that broke is not a clean
        repository, and SARIF says so directly."""
        payload = {"runs": [{"tool": {"driver": {"name": "codeql"}}, "invocations": [{"executionSuccessful": False}]}]}
        health = sarif_health(payload, "sarif")
        assert health.healthy is False
        assert "codeql" in health.summary()

    def test_absent_invocation_data_is_treated_as_healthy(self):
        """Matches both the SARIF default and the existing contract of the
        push endpoint: a CI job that posts results is asserting it ran."""
        assert sarif_health({"runs": [{"results": []}]}, "sarif").healthy is True
        assert sarif_health({}, "sarif").healthy is True

    def test_malformed_runs_do_not_explode(self):
        assert sarif_health({"runs": ["nonsense", None]}, "sarif").healthy is True


def test_findings_left_open_are_reported_to_the_caller(engine):
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
