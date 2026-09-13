"""A tool Toleman can execute is not automatically a tool it should assign.

noseyparker (#255) was assigned to every workspace's on-demand, CI and PR
guardrail surfaces by default, because `default_usage_for` derived that
purely from "is it in TOOL_COMMANDS". Two things were wrong with that at
once:

  * Its own registry entry says the opposite in prose -- "The cost is real
    and is why this is opt-in rather than default", 26 findings to gitleaks'
    0 on a clean checkout of this repo, almost all test fixtures and
    migration passwords. The stated intent and the actual default disagreed.
  * backend/Dockerfile deliberately does not bundle the binary (#385). So on
    the image this project ships, the tool could never run, and every single
    PR Guardrail comment carried "noseyparker failed to run; this PR was not
    fully scanned" -- forever, unactionably, which is exactly how a real
    tools_failed warning stops being read.

These pin both halves of the fix: it is off until an operator asks for it,
and if an operator does ask for it without installing it, the failure says
so instead of looking like a broken scanner.
"""

import subprocess
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.tool_registry import OPT_IN_TOOLS, USAGE_SURFACES, default_usage_for
from app.core.tool_usage import runnable_tools, tools_for_surface
from app.models.models import WorkspaceToolConfig
from app.scanners import runner


@pytest.fixture()
def session():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


class TestOptInToolsAreNotAssignedByDefault:
    def test_every_opt_in_tool_defaults_off_on_every_surface(self):
        for tool in OPT_IN_TOOLS:
            usage = default_usage_for(tool)
            assert usage == dict.fromkeys(USAGE_SURFACES, False), tool

    def test_an_opt_in_tool_is_still_genuinely_runnable(self):
        """Off by default, not absent: the distinction the whole fix rests on.
        A tool with no command or no parser would be a different bug (that is
        kics), and would make this default unremarkable rather than a choice."""
        assert OPT_IN_TOOLS <= runnable_tools()

    def test_noseyparker_is_not_assigned_to_a_fresh_workspace(self, session):
        for surface in USAGE_SURFACES:
            assert "noseyparker" not in tools_for_surface(session, 1, surface)

    def test_the_surfaces_it_shared_are_untouched(self, session):
        """The change must not take gitleaks -- the default secrets scanner,
        and the one that is actually bundled -- down with it."""
        tools = tools_for_surface(session, 1, "pr_guardrail")
        assert "gitleaks" in tools
        assert "semgrep" in tools

    def test_an_operator_can_still_turn_it_on(self, session):
        session.add(WorkspaceToolConfig(workspace_id=1, tool="noseyparker", pr_guardrail=True))
        session.commit()

        assert "noseyparker" in tools_for_surface(session, 1, "pr_guardrail")
        # Per-workspace, like every other assignment.
        assert "noseyparker" not in tools_for_surface(session, 2, "pr_guardrail")


class TestMissingBinaryReportsItself:
    def test_a_missing_binary_is_reported_as_not_installed(self, monkeypatch, tmp_path):
        """FileNotFoundError reaching the caller reads as a crashed scanner.
        The operator needs the one fact that makes it actionable."""
        def _missing(*args, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", "noseyparker")

        monkeypatch.setattr(runner.subprocess, "run", _missing)

        with pytest.raises(runner.ToolExecutionError) as exc:
            runner.run_tool("noseyparker", Path(tmp_path))

        assert "not installed on this deployment" in str(exc.value)
        assert "noseyparker" in str(exc.value)

    def test_it_is_still_a_failure_not_a_skip(self, monkeypatch, tmp_path):
        """A missing scanner is a real coverage gap. It must keep routing to
        tools_failed ("not fully scanned"), never to ToolNotApplicable, which
        renders as an expected, unremarkable skip."""
        def _missing(*args, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", "gitleaks")

        monkeypatch.setattr(runner.subprocess, "run", _missing)

        with pytest.raises(runner.ToolExecutionError):
            runner.run_tool("gitleaks", Path(tmp_path))

        assert not issubclass(runner.ToolNotApplicable, runner.ToolExecutionError)

    def test_a_tool_that_runs_is_unaffected(self, monkeypatch, tmp_path):
        """The wrapper must not swallow or reshape a normal result."""
        monkeypatch.setattr(
            runner.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(a[0] if a else [], 0, stdout="{}", stderr=""),
        )

        assert runner.run_tool("semgrep", Path(tmp_path)) == {}

    def test_handling_a_missing_binary_costs_the_run_no_health(self, monkeypatch, tmp_path):
        """The regression this pins is not the message, it is where the
        message lives.

        This change was first written against a `_execute` that predated
        #444: the not-installed handling was hoisted into a thin wrapper
        that delegated to a verbatim *copy* of the old body. Re-applied on
        top of #444 that shape still merges cleanly, still type-checks and
        still raises the right error -- while every health signal #229
        records inside `_execute` is left behind in the original, so a scan
        that produced nothing useful reads as a clean pass again and can
        mitigate live findings.

        The check that catches it is not about the missing binary at all:
        run a tool that *is* installed, through the same `_execute` the
        handler wraps, and require its health verdict to still arrive.
        """
        monkeypatch.setattr(
            runner.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(
                a[0] if a else [], 0, stdout="", stderr="WARN failed to download rule set",
            ),
        )

        raw, health = runner.run_tool_checked("semgrep", Path(tmp_path))

        assert raw == {}
        assert health.healthy is False
        # Both of the signals `_execute` itself folds into run.health: the
        # stderr marker, and the wrote-no-report heuristic. (The third, the
        # trivy DB assessment, lives in run_tool_checked; test_scan_health.py
        # owns it.)
        summary = health.summary()
        assert "failed to download" in summary
        assert "wrote no report" in summary
