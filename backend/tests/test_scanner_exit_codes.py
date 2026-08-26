"""A scanner that dies must never look like a scanner that found nothing (#253).

Found while benchmarking secret scanners against real binaries. gitleaks was
invoked with `--report-path /dev/stdout`; on a host where /dev/stdout is not
writable by the process it aborts *before scanning anything*:

    FTL Report path is not writable: /dev/stdout
    $ echo $?
    1

`run_tool` never looked at the return code. Empty stdout hit the
"no findings" default, so a file containing a live-format AWS key came back
as `[]`; a clean pass, with a green commit status, from a scanner that had
examined nothing.

Two fixes, both pinned here: check every tool's exit code, and stop using
/dev/stdout so the failure has no way to occur in the first place.

The rule is the one this codebase keeps restating:

    ran, found nothing   a real clean result
    did not run          ToolNotApplicable (#243)
    broke                ToolExecutionError; the check is unreliable
"""

import json
import subprocess

import pytest

from app.scanners import runner
from app.scanners.runner import ToolExecutionError


class TestExitCodeIsChecked:
    def _fake_proc(self, monkeypatch, returncode, stdout="", stderr=""):
        class P:
            pass

        p = P()
        p.returncode, p.stdout, p.stderr = returncode, stdout, stderr
        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: p)

    def test_nonzero_exit_raises_instead_of_reporting_clean(self, monkeypatch, tmp_path):
        self._fake_proc(monkeypatch, 1, stdout="", stderr="FTL something broke")
        with pytest.raises(ToolExecutionError) as ei:
            runner.run_tool("trivy", tmp_path)
        assert "exited 1" in str(ei.value)

    def test_the_failure_names_the_tool_and_the_cause(self, monkeypatch, tmp_path):
        self._fake_proc(monkeypatch, 2, stderr="could not load rules from /etc/x")
        with pytest.raises(ToolExecutionError) as ei:
            runner.run_tool("tfsec", tmp_path)
        msg = str(ei.value)
        assert "tfsec" in msg
        assert "could not load rules" in msg

    def test_semgrep_exit_1_means_findings_not_failure(self, monkeypatch, tmp_path):
        """semgrep documents 1 as "findings were reported". Treating it as a
        crash would mark every scan that found something as failed."""
        self._fake_proc(monkeypatch, 1, stdout=json.dumps({"results": [{"x": 1}]}))
        out = runner.run_tool("semgrep", tmp_path)
        assert out == {"results": [{"x": 1}]}

    def test_zero_exit_with_no_output_is_still_clean(self, monkeypatch, tmp_path):
        """The legitimate empty case must keep working; this fix must not
        turn quiet successes into failures."""
        self._fake_proc(monkeypatch, 0, stdout="")
        assert runner.run_tool("trivy", tmp_path) == {}

    def test_ansi_escapes_are_stripped_from_the_message(self, monkeypatch, tmp_path):
        """The message reaches scan records and PR comments; terminal colour
        codes there are unreadable noise."""
        self._fake_proc(monkeypatch, 1, stderr="\x1b[31mFTL\x1b[0m disk is full")
        with pytest.raises(ToolExecutionError) as ei:
            runner.run_tool("trivy", tmp_path)
        assert "\x1b[" not in str(ei.value)
        assert "disk is full" in str(ei.value)

    def test_every_wired_tool_declares_its_success_codes(self):
        """A tool added to TOOL_COMMANDS without an entry here silently opts
        out of the check and can regress to the #253 behaviour."""
        exempt = {"modelscan"}  # checks its own exit code in _run_modelscan
        missing = set(runner.TOOL_COMMANDS) - set(runner.TOOL_SUCCESS_EXIT_CODES) - exempt
        assert not missing, f"tools with no declared success exit codes: {sorted(missing)}"


class TestGitleaksReportPath:
    """The specific fragility that triggered #253."""

    def test_no_longer_writes_to_dev_stdout(self):
        cmd = runner.TOOL_COMMANDS["gitleaks"]("/repo")
        assert "/dev/stdout" not in cmd, (
            "gitleaks aborts before scanning where /dev/stdout is not writable, "
            "and used to report that as a clean result"
        )
        assert runner.GITLEAKS_REPORT_PLACEHOLDER in cmd

    def test_missing_report_after_success_is_an_error_not_a_pass(self, monkeypatch, tmp_path):
        """Exited 0 but wrote nothing. gitleaks writes a report on every real
        run, so this means something went wrong; it is not evidence of a
        clean repo."""
        class P:
            returncode, stdout, stderr = 0, "", ""

        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: P())
        with pytest.raises(ToolExecutionError) as ei:
            runner.run_tool("gitleaks", tmp_path)
        assert "no report" in str(ei.value).lower()

    def test_unreadable_report_is_an_error_not_a_pass(self, monkeypatch, tmp_path):
        def fake_run(cmd, **kwargs):
            path = [c for c in cmd if c.endswith("report.json")][0]
            open(path, "w").write("{not json")

            class P:
                returncode, stdout, stderr = 0, "", ""

            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        with pytest.raises(ToolExecutionError):
            runner.run_tool("gitleaks", tmp_path)

    def test_empty_report_is_a_genuine_clean_result(self, monkeypatch, tmp_path):
        def fake_run(cmd, **kwargs):
            path = [c for c in cmd if c.endswith("report.json")][0]
            open(path, "w").write("[]")

            class P:
                returncode, stdout, stderr = 0, "", ""

            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        assert runner.run_tool("gitleaks", tmp_path) == []

    def test_temp_report_directory_is_cleaned_up(self, monkeypatch, tmp_path):
        seen = {}

        def fake_run(cmd, **kwargs):
            path = [c for c in cmd if c.endswith("report.json")][0]
            seen["dir"] = str(__import__("pathlib").Path(path).parent)
            open(path, "w").write("[]")

            class P:
                returncode, stdout, stderr = 0, "", ""

            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        runner.run_tool("gitleaks", tmp_path)
        assert not __import__("os").path.exists(seen["dir"])


class TestFailureRoutesToNotFullyScanned:
    """The plumbing that turns the raised error into an honest report already
    existed; #253 was that the signal never reached it."""

    def test_a_broken_tool_lands_in_tools_failed(self, monkeypatch, tmp_path):
        from app.core import pr_guardrail_executor as executor

        def fake_run_tool(tool, repo_path, paths=None):
            if tool == "gitleaks":
                raise ToolExecutionError("gitleaks exited 1: disk is full")
            return {}

        monkeypatch.setattr(executor.runner, "run_tool", fake_run_tool)
        monkeypatch.setattr(
            executor.parsers, "PARSER_MAP", {"semgrep": lambda raw: [], "gitleaks": lambda raw: []}
        )
        _, failed, skipped = executor._run_guardrail_tools(["semgrep", "gitleaks"], tmp_path)
        assert failed == ["gitleaks"]
        assert skipped == {}, "a crash is not a skip"

    def test_tool_execution_error_is_not_confused_with_not_applicable(self):
        assert not issubclass(ToolExecutionError, runner.ToolNotApplicable)
        assert not issubclass(runner.ToolNotApplicable, ToolExecutionError)
        assert not issubclass(ToolExecutionError, subprocess.CalledProcessError)
