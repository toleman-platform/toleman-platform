"""Resolve which tools a given scan surface should actually run, from the
per-workspace usage assignments an operator sets in Tool Marketplace
(``WorkspaceToolConfig``, issue #75).

Until this module existed, those four checkboxes -- On-demand / API scan /
CI pipeline / PR guardrail -- were *write-only*. They persisted, they were
served back by ``GET /api/tools/assignments``, the UI rendered them ticked,
and nothing at execution time ever read them. PR Guardrail in particular
hardcoded ``GUARDRAIL_TOOL = "semgrep"``, so a workspace with Gitleaks
ticked for PR guardrail got a *ticked box for a tool that never ran*, and a
pull request adding a hardcoded AWS key passed clean. Found in an external
evaluation (finding GH-01); this module is the fix's foundation.

Resolution order for a (workspace, tool, surface) triple:

  1. a saved ``WorkspaceToolConfig`` row, if the operator has customized it;
  2. otherwise ``tool_registry.default_usage_for(tool)``, the built-in
     default (mirrors the "None = inherit" pattern used by enforcement mode).

On top of that, ``tools_for_surface`` only ever returns tools Toleman can
genuinely execute -- a key in ``runner.TOOL_COMMANDS`` *with* a parser in
``parsers.PARSER_MAP``. A registry-only entry like ``kics`` has nothing to
run; returning it would hand the caller a tool name that raises
``ValueError: unsupported tool`` the moment it tried.
"""

from sqlmodel import Session, select

from app.core.tool_registry import INTERNAL_TOOL_KEYS, TOOL_REGISTRY, USAGE_SURFACES, default_usage_for
from app.models.models import WorkspaceToolConfig
from app.scanners import parsers, runner


def runnable_tools() -> set[str]:
    """Tools with both a real command and a real parser, excluding internal
    invocation modes (``trivy-sbom``) that are not operator-facing tools."""
    return (set(runner.TOOL_COMMANDS) & set(parsers.PARSER_MAP)) - set(INTERNAL_TOOL_KEYS)


def is_nuclei_enabled_for_api_scan(session: Session, workspace_id: int) -> bool:
    """(#232) Active API Scanning's one and only surface check.

    nuclei cannot go through tools_for_surface: it structurally fails
    runnable_tools()'s TOOL_COMMANDS-membership test (its invocation takes a
    list of live URLs, built by app.core.api_scan_targets from already-
    discovered endpoints -- nothing like the repo-path shape every generic
    runner tool shares), so it can never appear in that function's result
    regardless of any assignment. This mirrors the same saved-row-else-
    default resolution on a single tool/surface pair instead.

    default_usage_for("nuclei")["api_scan"] is True (see its docstring),
    matching Active API Scanning's actual behavior since #72: it has always
    run unconditionally, gated only on api_base_url being configured. So an
    operator who has never touched this workspace's tool assignments keeps
    getting exactly what they already have; only an explicit, saved
    WorkspaceToolConfig row can turn it off.
    """
    cfg = session.exec(
        select(WorkspaceToolConfig).where(
            WorkspaceToolConfig.workspace_id == workspace_id,
            WorkspaceToolConfig.tool == "nuclei",
        )
    ).first()
    if cfg is not None:
        return cfg.api_scan
    return default_usage_for("nuclei")["api_scan"]


def tools_for_surface(session: Session, workspace_id: int, surface: str) -> list[str]:
    """Tools this workspace has enabled for ``surface`` and that can actually
    run, in ``TOOL_REGISTRY`` order (stable, so a PR comment's tool list
    doesn't reshuffle between scans).

    Returns ``[]`` when an operator has genuinely turned every tool off for
    this surface. Callers must treat that as "nothing was checked", NOT as
    "checked and clean" -- the distinction that ``osv_malware.py`` already
    draws between ``None`` and ``{}``, and the one whose absence made
    GH-01 a silent pass instead of a loud misconfiguration.
    """
    if surface not in USAGE_SURFACES:
        raise ValueError(f"unknown usage surface: {surface!r} (expected one of {USAGE_SURFACES})")

    saved = {
        c.tool: c
        for c in session.exec(
            select(WorkspaceToolConfig).where(WorkspaceToolConfig.workspace_id == workspace_id)
        ).all()
    }
    runnable = runnable_tools()

    out = []
    for entry in TOOL_REGISTRY:
        tool = entry["tool"]
        if tool not in runnable:
            continue
        cfg = saved.get(tool)
        enabled = getattr(cfg, surface) if cfg else default_usage_for(tool)[surface]
        if enabled:
            out.append(tool)
    return out
