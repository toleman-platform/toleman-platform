"""Diff-scoped PR scans (#243).

Scanning only a PR's changed files is a coverage *reduction* bought for
speed, not a free optimisation: a change in file A can make pre-existing
code in file B vulnerable, and a diff-scoped scan will not see it.

That makes the honesty properties the important ones to pin, more than the
speed. Three states must stay distinguishable everywhere they surface,
persisted columns, the PR comment, tools_run:

    ran, found nothing   a real clean result
    skipped              nothing was examined; not evidence of anything
    failed               the check is unreliable

Collapsing "skipped" into "ran" would make a trivy that never executed read
exactly like a trivy that ran clean. That is the false all-clear this
codebase keeps refusing (osv_malware.py, #229), arriving through a new door.
"""

import subprocess
from pathlib import Path

import pytest

from app.core import pr_guardrail_executor as executor
from app.models.models import PRGuardrailStatus
from app.scanners import runner
from app.scanners.runner import ToolNotApplicable


class TestManifestGating:
    """trivy resolves dependency manifests, so a file list means nothing to
    it. The real question is whether a manifest moved."""

    @pytest.mark.parametrize(
        "path",
        [
            "backend/requirements.txt",
            "frontend/package-lock.json",
            "go.mod",
            "Cargo.lock",
            "frontend/Dockerfile",
            "backend/Dockerfile.hardened",  # Dockerfile* prefix match
            "pyproject.toml",
        ],
    )
    def test_dependency_files_trigger_a_scan(self, path):
        assert runner.manifest_changed([path]) is True

    @pytest.mark.parametrize("path", ["README.md", "src/app.py", "docs/guide.mdx", "main.tf"])
    def test_ordinary_source_changes_do_not(self, path):
        assert runner.manifest_changed([path]) is False

    def test_lockfile_alone_counts(self):
        """The transitive-upgrade case (#239): the lockfile moves while the
        manifest does not. Missing this would reintroduce the exact blind
        spot that issue is about."""
        assert runner.manifest_changed(["poetry.lock"]) is True

    def test_trivy_skips_rather_than_reporting_clean(self, tmp_path):
        with pytest.raises(ToolNotApplicable) as ei:
            runner.run_tool("trivy", tmp_path, paths=["README.md"])
        assert "manifest" in str(ei.value).lower()

    def test_trivy_scans_the_whole_tree_when_a_manifest_moved(self, tmp_path, monkeypatch):
        """Scoping trivy to the manifest file itself would report only direct
        pins, the #239 blind spot. It must get the whole checkout."""
        seen = {}

        def fake_execute(tool, cmd, repo_path):
            seen["cmd"] = cmd
            return {}

        monkeypatch.setattr(runner, "_execute", fake_execute)
        runner.run_tool("trivy", tmp_path, paths=["requirements.txt"])
        assert str(tmp_path) in seen["cmd"]
        assert "requirements.txt" not in " ".join(seen["cmd"])


class TestPerToolScoping:
    def test_semgrep_receives_every_changed_file(self, tmp_path, monkeypatch):
        seen = {}
        monkeypatch.setattr(runner, "_execute", lambda t, c, p: seen.setdefault("cmd", c) or {})
        runner.run_tool("semgrep", tmp_path, paths=["a.py", "b.py"])
        assert str(tmp_path / "a.py") in seen["cmd"]
        assert str(tmp_path / "b.py") in seen["cmd"]
        # The unscoped trailing repo path must be gone, or we scan everything
        # while reporting a diff scan.
        assert seen["cmd"][-1] != str(tmp_path)

    def test_gitleaks_runs_once_per_file_and_merges(self, tmp_path, monkeypatch):
        calls = []

        def fake_execute(tool, cmd, repo_path):
            calls.append(cmd)
            return [{"finding": len(calls)}]

        monkeypatch.setattr(runner, "_execute", fake_execute)
        merged = runner.run_tool("gitleaks", tmp_path, paths=["a.py", "b.py", "c.py"])
        assert len(calls) == 3
        assert merged == [{"finding": 1}, {"finding": 2}, {"finding": 3}]

    def test_tfsec_ignores_files_it_cannot_read(self, tmp_path, monkeypatch):
        calls = []
        monkeypatch.setattr(runner, "_execute", lambda t, c, p: calls.append(c) or {})
        runner.run_tool("tfsec", tmp_path, paths=["main.tf", "app.py", "README.md"])
        assert len(calls) == 1, "only the .tf file should have been scanned"

    def test_tfsec_skips_when_no_terraform_changed(self, tmp_path):
        with pytest.raises(ToolNotApplicable):
            runner.run_tool("tfsec", tmp_path, paths=["app.py"])

    def test_checkov_uses_repeatable_f_not_d(self, tmp_path, monkeypatch):
        seen = {}
        monkeypatch.setattr(runner, "_execute", lambda t, c, p: seen.setdefault("cmd", c) or {})
        runner.run_tool("checkov", tmp_path, paths=["main.tf", "k8s.yaml"])
        assert "-d" not in seen["cmd"]
        assert seen["cmd"].count("-f") == 2

    def test_gosec_maps_files_to_packages(self):
        assert runner.go_packages_for(["util/db/db.go", "util/db/x.go"]) == ["./util/db"]

    def test_root_go_file_does_not_become_a_full_recursive_scan(self):
        """`./...` walks the entire module. Returning it for a root-level
        change would scan everything while still reporting "diff"."""
        assert "./..." not in runner.go_packages_for(["main.go"])

    def test_gosec_skips_when_no_go_changed(self, tmp_path):
        with pytest.raises(ToolNotApplicable):
            runner.run_tool("gosec", tmp_path, paths=["app.py"])

    def test_unscoped_call_is_unchanged(self, tmp_path, monkeypatch):
        """paths=None must reproduce the old command exactly, scheduled and
        default-branch scans still scan everything."""
        seen = {}
        monkeypatch.setattr(runner, "_execute", lambda t, c, p: seen.setdefault("cmd", c) or {})
        runner.run_tool("semgrep", tmp_path)
        assert seen["cmd"] == runner.TOOL_COMMANDS["semgrep"](str(tmp_path))


class TestSkippedIsNotPassed:
    """The core honesty property."""

    def test_skipped_tool_is_not_counted_as_run(self, tmp_path, monkeypatch):
        def fake_run_tool(tool, repo_path, paths=None):
            if tool == "trivy":
                raise ToolNotApplicable("no manifest changed")
            return {}

        monkeypatch.setattr(executor.runner, "run_tool", fake_run_tool)
        monkeypatch.setattr(executor.parsers, "PARSER_MAP", {"semgrep": lambda raw: [], "trivy": lambda raw: []})

        findings, failed, skipped = executor._run_guardrail_tools(
            ["semgrep", "trivy"], tmp_path, paths=["a.py"]
        )
        assert failed == [], "skipped is not a failure"
        assert "trivy" in skipped
        assert "semgrep" not in skipped

    def test_skipped_is_distinct_from_failed(self, tmp_path, monkeypatch):
        def fake_run_tool(tool, repo_path, paths=None):
            if tool == "trivy":
                raise ToolNotApplicable("no manifest changed")
            if tool == "gitleaks":
                raise RuntimeError("gitleaks exploded")
            return {}

        monkeypatch.setattr(executor.runner, "run_tool", fake_run_tool)
        monkeypatch.setattr(
            executor.parsers, "PARSER_MAP",
            {t: (lambda raw: []) for t in ("semgrep", "trivy", "gitleaks")},
        )

        _, failed, skipped = executor._run_guardrail_tools(
            ["semgrep", "trivy", "gitleaks"], tmp_path, paths=["a.py"]
        )
        assert failed == ["gitleaks"]
        assert list(skipped) == ["trivy"]

    def test_tool_not_applicable_is_not_a_tool_execution_error(self):
        """If it subclassed ToolExecutionError, every skip would mark the
        scan failed; if it were caught by the generic handler it would be
        reported as a broken scanner. It must be neither."""
        assert not issubclass(ToolNotApplicable, runner.ToolExecutionError)
        assert not issubclass(ToolNotApplicable, subprocess.CalledProcessError)


class TestCommentTellsTheTruth:
    def test_diff_scope_is_stated_before_the_result(self):
        body = executor.render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"], scan_scope="diff", files_scanned=7,
        )
        assert "Diff-scoped scan" in body
        assert "7 file(s)" in body
        # Above the verdict, not buried under it.
        assert body.index("Diff-scoped") < body.index("No net-new")

    def test_diff_scoped_clean_result_carries_no_green_tick(self):
        """A ✅ next to a partial scan is the false all-clear in one glyph."""
        body = executor.render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"], scan_scope="diff", files_scanned=3,
        )
        assert "✅" not in body
        assert "changed files" in body

    def test_full_scan_still_says_all_clear(self):
        body = executor.render_comment([], [], PRGuardrailStatus.PASSED, 1, 1, tools_run=["semgrep"])
        assert "✅" in body
        assert "Diff-scoped" not in body

    def test_skipped_tools_are_named_with_their_reason(self):
        body = executor.render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"],
            tools_skipped={"trivy": "no dependency manifest changed"},
            scan_scope="diff", files_scanned=2,
        )
        assert "trivy" in body
        assert "no dependency manifest changed" in body

    def test_skipped_tool_never_appears_as_scanned_with(self):
        body = executor.render_comment(
            [], [], PRGuardrailStatus.PASSED, 1, 1,
            tools_run=["semgrep"],
            tools_skipped={"trivy": "no dependency manifest changed"},
            scan_scope="diff", files_scanned=2,
        )
        scanned_line = [ln for ln in body.splitlines() if "Scanned with" in ln][0]
        assert "trivy" not in scanned_line

    def test_default_arguments_reproduce_the_old_comment(self):
        """Callers predating #243 must render exactly what they used to."""
        old = executor.render_comment([], [], PRGuardrailStatus.PASSED, 1, 1, tools_run=["semgrep"])
        assert "Diff-scoped" not in old
        assert "Not run for this PR" not in old


class TestChangedFiles:
    def _fake_github_get(self, monkeypatch, pages):
        calls = {"n": 0}

        class Res:
            def __init__(self, data):
                self._data = data

            def raise_for_status(self):
                pass

            def json(self):
                return self._data

        def fake_get(path):
            idx = calls["n"]
            calls["n"] += 1
            return Res(pages[idx] if idx < len(pages) else [])

        monkeypatch.setattr(executor, "github_get", fake_get)
        return calls

    def test_deleted_files_are_excluded(self, monkeypatch):
        self._fake_github_get(monkeypatch, [[
            {"filename": "kept.py", "status": "modified"},
            {"filename": "gone.py", "status": "removed"},
        ]])
        assert executor._changed_files("o/r", 1) == ["kept.py"]

    def test_api_failure_returns_none_not_empty(self, monkeypatch):
        """None means "fall back to a full scan". An empty list would mean
        "nothing changed", which would scan nothing and pass."""
        def boom(path):
            raise RuntimeError("GitHub is down")

        monkeypatch.setattr(executor, "github_get", boom)
        assert executor._changed_files("o/r", 1) is None

    def test_pagination_is_followed(self, monkeypatch):
        page1 = [{"filename": f"f{i}.py", "status": "modified"} for i in range(100)]
        page2 = [{"filename": "last.py", "status": "modified"}]
        self._fake_github_get(monkeypatch, [page1, page2])
        result = executor._changed_files("o/r", 1)
        assert len(result) == 101
        assert result[-1] == "last.py"


class TestFallbacks:
    def test_large_prs_fall_back_to_full(self):
        """A 500-file PR is not a diff, and the per-file tools would spawn a
        process per file."""
        assert executor.MAX_DIFF_SCOPED_FILES > 0
        assert executor.MAX_DIFF_SCOPED_FILES <= 1000

    def test_targets_default_to_full_scans(self):
        from app.models.models import Target

        assert Target.model_fields["diff_scoped_pr_scans"].default is False, (
            "diff scoping reduces coverage; it must be opted into per target"
        )

    def test_scans_default_to_recording_full_scope(self):
        from app.models.models import PRGuardrailScan

        assert PRGuardrailScan.model_fields["scan_scope"].default == "full"
