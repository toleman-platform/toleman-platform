"""Tests for model-file scanning (issue #186).

The parser fixtures are pinned against a REAL `modelscan 0.8.8 -r json` run
against a pickle whose __reduce__ calls os.system -- not a schema invented
from the docs, which don't publish one. Regenerate with:

    python -c "import pickle,os
    class E:
        def __reduce__(self): return (os.system, ('echo pwned',))
    open('unsafe.pkl','wb').write(pickle.dumps(E()))"
    modelscan -p . -r json -o report.json

The malicious pickle is generated at test time rather than committed: a real
hostile model file checked into the repo would be flagged by this project's
own CI scanners, correctly.
"""
import json
import subprocess
from pathlib import Path

import pytest

from app.models.models import Severity
from app.scanners.parsers import parse_modelscan
from app.scanners.runner import MODELSCAN_REPORT_PLACEHOLDER, ToolExecutionError, _run_modelscan

# Verbatim from a real modelscan 0.8.8 run.
REAL_UNSAFE_REPORT = {
    "summary": {
        "total_issues_by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1},
        "total_issues": 1,
        "input_path": "/tmp/msfix",
        "absolute_path": "/tmp/msfix",
        "modelscan_version": "0.8.8",
        "timestamp": "2026-08-16T22:13:50.967738",
        "scanned": {"total_scanned": 2, "scanned_files": ["clean.pkl", "unsafe.pkl"]},
    },
    "issues": [
        {
            "description": "Use of unsafe operator 'system' from module 'posix'",
            "operator": "system",
            "module": "posix",
            "source": "unsafe.pkl",
            "scanner": "modelscan.scanners.PickleUnsafeOpScan",
            "severity": "CRITICAL",
        }
    ],
    "errors": [],
}

REAL_CLEAN_REPORT = {
    "summary": {
        "total_issues_by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "total_issues": 0,
        "input_path": "/tmp/msfix/empty",
        "modelscan_version": "0.8.8",
        "scanned": {"total_scanned": 0},
    },
    "issues": [],
    "errors": [],
}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_unsafe_operator_becomes_a_critical_finding():
    findings = parse_modelscan(REAL_UNSAFE_REPORT)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == Severity.CRITICAL
    assert f["file_path"] == "unsafe.pkl"
    assert "posix.system" in f["title"]
    assert f["rule_id"] == "modelscan.scanners.PickleUnsafeOpScan"


def test_clean_report_produces_no_findings():
    assert parse_modelscan(REAL_CLEAN_REPORT) == []


def test_missing_issues_key_is_tolerated():
    assert parse_modelscan({}) == []
    assert parse_modelscan({"issues": None}) == []


def test_no_line_number_is_reported_rather_than_fabricated():
    """The finding is the file itself; modelscan reports no line. Emitting a
    fake line 1 would send a reader to a meaningless offset in a binary."""
    f = parse_modelscan(REAL_UNSAFE_REPORT)[0]
    assert f["line_start"] is None
    assert f["line_end"] is None


def test_arbitrary_code_operator_is_floored_at_critical_even_if_downgraded():
    """The severity floor is applied independently of what modelscan says,
    so a settings file or a future retune of its ratings can't quietly
    downgrade an arbitrary-code-execution primitive."""
    downgraded = {
        "issues": [
            {
                "description": "Use of unsafe operator 'system' from module 'os'",
                "operator": "system",
                "module": "os",
                "source": "m.pkl",
                "scanner": "modelscan.scanners.PickleUnsafeOpScan",
                "severity": "LOW",
            }
        ]
    }
    assert parse_modelscan(downgraded)[0]["severity"] == Severity.CRITICAL


def test_non_code_execution_operator_keeps_its_reported_severity():
    """The floor is targeted, not a blanket 'everything is Critical' -- that
    is how a signal turns into wallpaper."""
    other = {
        "issues": [
            {
                "description": "Something less severe",
                "operator": "SomeOtherOp",
                "module": "numpy.core",
                "source": "m.pkl",
                "scanner": "modelscan.scanners.PickleUnsafeOpScan",
                "severity": "MEDIUM",
            }
        ]
    }
    assert parse_modelscan(other)[0]["severity"] == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Runner: modelscan's non-standard exit codes
# ---------------------------------------------------------------------------


def _fake_run(returncode: int, report: dict | None, report_arg_index: int = -1):
    """Patch target for subprocess.run that also writes the report file the
    real modelscan would have written."""

    def _run(cmd, capture_output=True, text=True, **kwargs):
        if report is not None:
            Path(cmd[report_arg_index]).write_text(json.dumps(report))

        class Proc:
            pass

        proc = Proc()
        proc.returncode = returncode
        proc.stdout = ""
        proc.stderr = ""
        return proc

    return _run


def _cmd():
    return ["modelscan", "-p", "/repo", "-r", "json", "-o", MODELSCAN_REPORT_PLACEHOLDER]


def test_exit_1_is_success_with_findings_not_a_failure(monkeypatch):
    """Exit 1 means 'scan ok, vulnerabilities found'. Treating it as an error
    would discard exactly the findings this tool exists to produce -- the
    hazard checkov/tfsec avoid with --soft-fail, which modelscan lacks."""
    monkeypatch.setattr(subprocess, "run", _fake_run(1, REAL_UNSAFE_REPORT))
    raw = _run_modelscan(_cmd())
    assert len(raw["issues"]) == 1


def test_exit_0_clean_scan(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(0, REAL_CLEAN_REPORT))
    assert _run_modelscan(_cmd())["issues"] == []


def test_exit_3_no_supported_files_is_a_clean_success(monkeypatch):
    """A repo with no model files is legitimately clean, not an error and
    not a silent skip."""
    monkeypatch.setattr(subprocess, "run", _fake_run(3, None))
    raw = _run_modelscan(_cmd())
    assert raw["issues"] == []
    assert raw["summary"]["total_issues"] == 0


@pytest.mark.parametrize("code", [2, 4])
def test_real_failures_raise_rather_than_reporting_clean(monkeypatch, code):
    """Exit 2 (modelscan errored) and 4 (bad options) must surface as failed
    scans. Recording them as zero findings would be a false all-clear."""
    monkeypatch.setattr(subprocess, "run", _fake_run(code, None))
    with pytest.raises(ToolExecutionError):
        _run_modelscan(_cmd())


def test_unreadable_report_raises(monkeypatch):
    def _run(cmd, capture_output=True, text=True, **kwargs):
        Path(cmd[-1]).write_text("not json{{{")

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    monkeypatch.setattr(subprocess, "run", _run)
    with pytest.raises(ToolExecutionError):
        _run_modelscan(_cmd())


# ---------------------------------------------------------------------------
# End-to-end against the real binary, if it's installed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    subprocess.run(["which", "modelscan"], capture_output=True).returncode != 0,
    reason="modelscan not installed",
)
def test_real_modelscan_detects_a_generated_malicious_pickle(tmp_path):
    """No mock data: builds a genuinely unsafe pickle, runs the real binary,
    and asserts we surface it as Critical. The pickle is never loaded."""
    import os
    import pickle

    class Evil:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    (tmp_path / "unsafe.pkl").write_bytes(pickle.dumps(Evil()))
    (tmp_path / "clean.pkl").write_bytes(pickle.dumps({"weights": [1, 2, 3]}))

    raw = _run_modelscan(["modelscan", "-p", str(tmp_path), "-r", "json", "-o", MODELSCAN_REPORT_PLACEHOLDER])
    findings = parse_modelscan(raw)

    assert len(findings) == 1
    assert findings[0]["severity"] == Severity.CRITICAL
    assert findings[0]["file_path"].endswith("unsafe.pkl")
