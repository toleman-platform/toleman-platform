"""Tests for app.core.tool_usage -- the resolver that makes Tool Marketplace's
per-tool usage-assignment checkboxes actually govern what runs.

Before this existed the four checkboxes (on-demand / API scan / CI pipeline /
PR guardrail) were write-only: persisted, served back by the assignments API,
rendered ticked in the UI, and never read by any scan surface. An external
evaluation caught the security-visible half of that (finding GH-01): a
workspace with Gitleaks ticked for PR guardrail got a *ticked box for a tool
that never ran*, and a pull request adding a hardcoded AWS key passed clean.
"""

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.tool_registry import TOOL_REGISTRY, default_usage_for
from app.core.tool_usage import runnable_tools, tools_for_surface
from app.models.models import WorkspaceToolConfig


@pytest.fixture()
def session():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def test_defaults_apply_when_workspace_has_no_saved_rows(session):
    tools = tools_for_surface(session, workspace_id=1, surface="pr_guardrail")
    # Absence of rows means "use the built-in default", not "disabled".
    assert "semgrep" in tools
    assert "gitleaks" in tools


def test_saved_row_overrides_the_default(session):
    session.add(WorkspaceToolConfig(workspace_id=1, tool="gitleaks", pr_guardrail=False))
    session.commit()

    tools = tools_for_surface(session, workspace_id=1, surface="pr_guardrail")
    assert "gitleaks" not in tools
    assert "semgrep" in tools  # untouched tools still resolve to their default


def test_a_saved_row_only_affects_its_own_workspace(session):
    session.add(WorkspaceToolConfig(workspace_id=1, tool="gitleaks", pr_guardrail=False))
    session.commit()

    assert "gitleaks" not in tools_for_surface(session, 1, "pr_guardrail")
    assert "gitleaks" in tools_for_surface(session, 2, "pr_guardrail")


def test_enabling_a_tool_off_by_default_surfaces_it(session):
    # api_scan defaults to False for every tool (see default_usage_for).
    assert tools_for_surface(session, 1, "api_scan") == []

    session.add(WorkspaceToolConfig(workspace_id=1, tool="semgrep", api_scan=True))
    session.commit()

    assert tools_for_surface(session, 1, "api_scan") == ["semgrep"]


def test_registry_only_tools_are_never_returned(session):
    # kics is catalogued for visibility but has no TOOL_COMMANDS entry --
    # returning it would hand the caller a name that raises
    # "unsupported tool" the moment it tried to run it.
    assert "kics" not in runnable_tools()

    session.add(WorkspaceToolConfig(workspace_id=1, tool="kics", pr_guardrail=True))
    session.commit()

    assert "kics" not in tools_for_surface(session, 1, "pr_guardrail")


def test_internal_invocation_modes_are_never_returned(session):
    # trivy-sbom is trivy with --format cyclonedx, dispatched only by the
    # SBOM pipeline. Offering it as a scan tool would return SBOM components
    # parsed as findings.
    assert "trivy-sbom" not in runnable_tools()
    assert "trivy-sbom" not in tools_for_surface(session, 1, "on_demand_scan")


def test_every_returned_tool_is_actually_runnable(session):
    for surface in ("on_demand_scan", "ci_pipeline", "api_scan", "pr_guardrail"):
        for tool in tools_for_surface(session, 1, surface):
            assert tool in runnable_tools(), f"{tool} returned for {surface} but cannot run"


def test_turning_everything_off_returns_empty_not_a_default(session):
    # An operator who genuinely disables every tool must get [] -- callers
    # have to be able to tell "nothing was checked" from "checked and clean".
    for entry in TOOL_REGISTRY:
        session.add(WorkspaceToolConfig(workspace_id=1, tool=entry["tool"], pr_guardrail=False))
    session.commit()

    assert tools_for_surface(session, 1, "pr_guardrail") == []


def test_unknown_surface_raises(session):
    with pytest.raises(ValueError):
        tools_for_surface(session, 1, "not_a_surface")


def test_resolution_order_is_stable_registry_order(session):
    tools = tools_for_surface(session, 1, "pr_guardrail")
    registry_order = [e["tool"] for e in TOOL_REGISTRY if e["tool"] in tools]
    assert tools == registry_order


def test_defaults_match_default_usage_for(session):
    # The resolver must not invent its own defaults -- it has to agree with
    # the single source of truth the assignments API also reads.
    for entry in TOOL_REGISTRY:
        tool = entry["tool"]
        if tool not in runnable_tools():
            continue
        for surface in ("on_demand_scan", "ci_pipeline", "api_scan", "pr_guardrail"):
            expected = default_usage_for(tool)[surface]
            actual = tool in tools_for_surface(session, 1, surface)
            assert actual == expected, f"{tool}/{surface}: resolver {actual} != default {expected}"
