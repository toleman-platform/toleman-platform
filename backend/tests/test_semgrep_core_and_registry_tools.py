"""Wiring for the two Semgrep rule layers Toleman ships (#201-adjacent).

`semgrep-core` is Toleman's own 94-rule pack; `semgrep-registry` is the
public semgrep-rules registry pruned to a repository's actual languages and
frameworks. They are separate tools rather than extra --config flags on one
entry, for the reason semgrep-llm already is: a Finding carries the tool
that produced it, so per-tool coverage, usage assignment and triage can
tell Toleman's narrow app-specific rules apart from the registry's broad
generic ones.

Two behaviours here are load-bearing and easy to regress:

  - Inline suppression is disabled on both. Toleman never honours a
    `# nosemgrep` comment; an ignore is requested and approved in the
    dashboard, where it carries an approval trail and can be revoked.
  - An unprovisioned registry is ToolNotApplicable, never an empty scan.
    semgrep with no --config scans nothing and exits 0, which ingests as a
    clean sweep and mitigates every open finding the tool previously
    reported -- a false all-clear, which this codebase treats as worse than
    a loud failure.
"""
from pathlib import Path
from unittest import mock

import pytest

from app.core.tool_registry import default_usage_for
from app.scanners import runner
from app.scanners.runner import ToolNotApplicable


def test_both_layers_are_runnable_tools():
    assert "semgrep-core" in runner.TOOL_COMMANDS
    assert "semgrep-registry" in runner.TOOL_COMMANDS


def test_core_pack_runs_the_in_repo_rules_with_suppression_disabled():
    cmd = runner.TOOL_COMMANDS["semgrep-core"]("/some/repo")

    assert "--disable-nosem" in cmd
    assert any(str(runner.CORE_RULES_DIR) in arg for arg in cmd)
    assert cmd[-1] == "/some/repo"


def test_the_core_rules_directory_actually_exists():
    """The command above is a lambda, so a typo'd path fails only at scan
    time, on a real scan, as an opaque semgrep error."""
    assert Path(runner.CORE_RULES_DIR).is_dir()
    assert any(Path(runner.CORE_RULES_DIR).rglob("*.yaml"))


def test_registry_layer_passes_one_config_per_language_and_disables_suppression():
    with mock.patch.object(runner, "registry_configs_for", return_value=["/c/python.yaml", "/c/ts.yaml"]):
        cmd = runner.TOOL_COMMANDS["semgrep-registry"]("/some/repo")

    assert [a for a in cmd if a.startswith("--config=")] == [
        "--config=/c/python.yaml",
        "--config=/c/ts.yaml",
    ]
    assert "--disable-nosem" in cmd


def test_an_unprovisioned_registry_is_not_applicable_rather_than_an_empty_scan(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")

    with mock.patch.object(runner, "registry_configs_for", return_value=[]):
        with pytest.raises(ToolNotApplicable):
            runner._run_tool_inner("semgrep-registry", tmp_path, None, mock.Mock())


def test_registry_configs_are_empty_when_the_clone_is_missing(tmp_path):
    """Not an exception: a fresh install has no vendored clone, and a repo
    can legitimately be in a language the registry has no folder for."""
    (tmp_path / "app.py").write_text("x = 1\n")

    with mock.patch.dict("os.environ", {"SEMGREP_RULES_REGISTRY_ROOT": str(tmp_path / "nope")}):
        assert runner.registry_configs_for(str(tmp_path)) == []


def test_registry_layer_defaults_off_where_a_developer_is_waiting():
    """CI and PR Guardrail gate a merge, so wall-clock is the constraint
    there. The registry layer roughly triples the applicable rule set and
    carries several times the taint-mode rules -- worth minutes on a
    nightly run, not worth it on a pull request."""
    usage = default_usage_for("semgrep-registry")

    assert usage["on_demand_scan"] is True
    assert usage["ci_pipeline"] is False
    assert usage["pr_guardrail"] is False


def test_the_core_pack_runs_on_every_repo_surface():
    usage = default_usage_for("semgrep-core")

    assert usage["on_demand_scan"] is True
    assert usage["ci_pipeline"] is True
    assert usage["pr_guardrail"] is True


def test_neither_layer_is_assigned_to_active_api_scanning():
    """api_scan takes a URL list, not a repo path; nuclei is the only tool
    with that shape."""
    assert default_usage_for("semgrep-core")["api_scan"] is False
    assert default_usage_for("semgrep-registry")["api_scan"] is False


def test_both_layers_get_semgrep_cache_isolation():
    """Same binary writing the same settings file as semgrep/semgrep-llm,
    so two concurrent runs race the same way."""
    assert "semgrep-core" in runner.TOOL_CACHE_ISOLATION
    assert "semgrep-registry" in runner.TOOL_CACHE_ISOLATION


def test_both_layers_are_diff_scopable():
    """MULTI_PATH: a diff-scoped scan can hand semgrep the changed paths
    instead of the whole checkout, which is most of what keeps the CI
    surface fast."""
    assert runner.TOOL_SCOPING["semgrep-core"] == runner.MULTI_PATH
    assert runner.TOOL_SCOPING["semgrep-registry"] == runner.MULTI_PATH
