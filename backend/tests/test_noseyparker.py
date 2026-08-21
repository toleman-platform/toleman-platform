"""noseyparker as a second secrets scanner (#255).

Benchmarked against gitleaks, trufflehog and detect-secrets on a 14-secret
ground-truth corpus with false-positive traps. gitleaks stays the default on
precision; noseyparker is the recall option, and the only one of the four
with a rule for credentials embedded in a database connection URI -- a real
gap in what we ship today.

Its output shape differs from every other tool here in two ways worth
pinning: the report is finding-oriented (one entry per secret, with a list of
every place it occurs) rather than match-oriented, and it is produced by a
second command reading a datastore the first command wrote.
"""

import json
import subprocess

import pytest

from app.scanners import parsers, runner
from app.scanners.runner import ToolExecutionError

# Shape captured from noseyparker 0.24.0's real report output.
REPORT = [
    {
        "finding_id": "abc",
        "rule_name": "GitHub Personal Access Token",
        "num_matches": 2,
        "matches": [
            {
                "provenance": [{"kind": "file", "path": "/repo/a.py"}],
                "location": {"source_span": {"start": {"line": 3, "column": 5},
                                             "end": {"line": 3, "column": 45}}},
                "snippet": {"before": "", "matching": "ghp_" + "x" * 36, "after": ""},
            },
            {
                "provenance": [{"kind": "file", "path": "/repo/b.py"}],
                "location": {"source_span": {"start": {"line": 9, "column": 1},
                                             "end": {"line": 9, "column": 40}}},
                "snippet": {"before": "", "matching": "ghp_" + "y" * 36, "after": ""},
            },
        ],
    }
]


class TestParser:
    def test_one_finding_per_match_not_per_secret(self):
        """The report groups by secret; triage needs one row per place it
        occurs. Two files leaking the same key are two things to fix, not one
        that is half-done after the first edit."""
        out = parsers.parse_noseyparker(REPORT)
        assert len(out) == 2
        assert {f["file_path"] for f in out} == {"/repo/a.py", "/repo/b.py"}

    def test_line_numbers_come_from_the_source_span(self):
        out = parsers.parse_noseyparker(REPORT)
        assert out[0]["line_start"] == 3
        assert out[1]["line_start"] == 9

    def test_rule_name_becomes_the_rule_id(self):
        assert parsers.parse_noseyparker(REPORT)[0]["rule_id"] == "GitHub Personal Access Token"

    def test_severity_is_high_like_gitleaks(self):
        """A committed credential is not a gradient. noseyparker carries a
        `score`, but it was null on every match in the benchmark corpus, so
        deriving severity from it would invent a signal that is not there."""
        from app.models.models import Severity

        assert all(f["severity"] == Severity.HIGH for f in parsers.parse_noseyparker(REPORT))

    def test_snippet_is_truncated(self):
        """The snippet *is* the secret. A whole PEM key in a finding row, a PR
        comment and a SIEM export is both noise and needless exposure."""
        big = [{
            "rule_name": "Private Key",
            "matches": [{
                "provenance": [{"path": "/repo/id_rsa"}],
                "location": {"source_span": {"start": {"line": 1}, "end": {"line": 30}}},
                "snippet": {"matching": "A" * 5000},
            }],
        }]
        assert len(parsers.parse_noseyparker(big)[0]["snippet"]) <= 200

    def test_empty_and_malformed_input_do_not_raise(self):
        assert parsers.parse_noseyparker([]) == []
        assert parsers.parse_noseyparker(None) == []
        assert parsers.parse_noseyparker([{"rule_name": "x"}]) == []

    def test_missing_provenance_does_not_raise(self):
        weird = [{"rule_name": "x", "matches": [{"location": {}, "snippet": {}}]}]
        assert parsers.parse_noseyparker(weird)[0]["file_path"] == ""


class TestWiring:
    def test_registered_everywhere_a_tool_must_be(self):
        assert "noseyparker" in runner.TOOL_COMMANDS
        assert "noseyparker" in parsers.PARSER_MAP
        assert "noseyparker" in runner.TOOL_SCOPING
        assert "noseyparker" in runner.TOOL_SUCCESS_EXIT_CODES

    def test_is_in_the_marketplace_registry(self):
        from app.core.tool_registry import TOOL_REGISTRY

        entry = next(t for t in TOOL_REGISTRY if t["tool"] == "noseyparker")
        assert entry["category"] == "Secrets"

    def test_scan_command_uses_the_datastore_placeholder(self):
        cmd = runner.TOOL_COMMANDS["noseyparker"]("/repo")
        assert runner.NOSEYPARKER_DATASTORE_PLACEHOLDER in cmd
        assert "/repo" in cmd


class TestFailuresAreNotCleanPasses:
    """#253's rule, applied to the two-step shape: a scan that died leaves an
    empty datastore, and an empty datastore renders as []."""

    def test_failed_scan_raises_rather_than_returning_empty(self, monkeypatch, tmp_path):
        class P:
            returncode, stdout, stderr = 1, "", "could not open datastore"

        monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: P())
        with pytest.raises(ToolExecutionError) as ei:
            runner.run_tool("noseyparker", tmp_path)
        assert "scan exited 1" in str(ei.value)

    def test_failed_report_raises(self, monkeypatch, tmp_path):
        calls = {"n": 0}

        def fake_run(cmd, **kwargs):
            calls["n"] += 1

            class P:
                returncode = 0 if calls["n"] == 1 else 2
                stdout = ""
                stderr = "report failed"

            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        with pytest.raises(ToolExecutionError) as ei:
            runner.run_tool("noseyparker", tmp_path)
        assert "report exited 2" in str(ei.value)

    def test_unreadable_json_raises(self, monkeypatch, tmp_path):
        calls = {"n": 0}

        def fake_run(cmd, **kwargs):
            calls["n"] += 1

            class P:
                returncode = 0
                stdout = "" if calls["n"] == 1 else "{not json"
                stderr = ""

            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        with pytest.raises(ToolExecutionError):
            runner.run_tool("noseyparker", tmp_path)

    def test_genuinely_empty_report_is_a_clean_result(self, monkeypatch, tmp_path):
        def fake_run(cmd, **kwargs):
            class P:
                returncode, stdout, stderr = 0, "[]", ""

            return P()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        assert runner.run_tool("noseyparker", tmp_path) == []
