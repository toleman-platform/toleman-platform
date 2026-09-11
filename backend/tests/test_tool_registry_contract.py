"""Structural guarantees about the tool registry.

These run anywhere, unlike `scripts/verify_tools.py`, which executes each
bundled tool and therefore only means anything inside the built image. The
split is deliberate: this file catches a malformed or drifting registry on
every PR in milliseconds, and the script catches a tool that is declared but
not actually usable, which no amount of static checking can tell you.

The thing both are guarding against is the same. A scanner that is missing or
broken does not announce itself; `run_scan` catches the failure, the scan
completes, and the repo shows zero findings. Zero findings from a broken
scanner looks exactly like zero findings from clean code.
"""
import shutil

import pytest

from app.core.tool_registry import (
    BUNDLED_TOOLS,
    TOOL_REGISTRY,
    UNKNOWN_TOOL_CATEGORY,
    USAGE_SURFACES,
    all_categories,
    all_known_tools,
    default_usage_for,
    registry_with_integration_status,
    tool_category,
    tools_in_category,
)
from app.scanners.runner import TOOL_COMMANDS

REQUIRED_FIELDS = (
    "tool",
    "display_name",
    "category",
    "languages",
    "description",
    "install_cmd",
    "docs_url",
    "version_cmd",
)

ALL_TOOLS = [entry["tool"] for entry in TOOL_REGISTRY]


def test_registry_is_not_empty():
    assert TOOL_REGISTRY


@pytest.mark.parametrize("entry", TOOL_REGISTRY, ids=ALL_TOOLS)
def test_every_entry_has_the_required_fields(entry):
    for field in REQUIRED_FIELDS:
        assert entry.get(field), f"{entry.get('tool')!r} is missing {field!r}"


@pytest.mark.parametrize("entry", TOOL_REGISTRY, ids=ALL_TOOLS)
def test_version_cmd_is_an_argv_list_not_a_string(entry):
    # A string would be split by a shell somewhere down the line. Every
    # subprocess call in this codebase passes argv lists precisely so no
    # shell ever parses these; see runner.clone_repo's same rule.
    cmd = entry["version_cmd"]
    assert isinstance(cmd, list) and cmd, f"{entry['tool']}: version_cmd must be a non-empty list"
    assert all(isinstance(part, str) for part in cmd)


@pytest.mark.parametrize("entry", TOOL_REGISTRY, ids=ALL_TOOLS)
def test_docs_url_is_https(entry):
    assert entry["docs_url"].startswith("https://"), entry["tool"]


def test_tool_names_are_unique():
    # `tool` is the join key for Scan.tool / Finding.tool / TOOL_COMMANDS. A
    # duplicate would silently merge two tools' findings.
    assert len(ALL_TOOLS) == len(set(ALL_TOOLS))


def test_integrated_flag_is_derived_not_hand_maintained():
    for entry in registry_with_integration_status():
        assert entry["integrated"] == (entry["tool"] in TOOL_COMMANDS), entry["tool"]


def test_every_runnable_tool_is_in_the_registry():
    # The registry is what the marketplace shows. A tool Toleman can dispatch
    # but never lists is invisible to the operator who has to install it, so
    # adding a real scanner without listing it still fails here.
    missing = sorted(set(TOOL_COMMANDS) - set(ALL_TOOLS))
    assert not missing, f"runnable but not in the registry: {missing}"


def test_bundled_tools_all_exist_in_the_registry():
    assert not sorted(BUNDLED_TOOLS - set(ALL_TOOLS))


def test_bundled_tools_are_all_integrated():
    # Shipping a tool in the image that Toleman cannot dispatch is dead
    # weight in the image and a misleading "installed" tick in the UI.
    not_runnable = sorted(t for t in BUNDLED_TOOLS if t not in TOOL_COMMANDS)
    assert not not_runnable, f"bundled but not runnable: {not_runnable}"


def test_non_integrated_tools_default_every_usage_surface_off():
    # A registry-only tool defaulting to enabled is a silent no-op that reads
    # to an admin as active coverage.
    #
    # nuclei (#232) is the one deliberate exception, not a violation of the
    # rule: it is not in TOOL_COMMANDS because its invocation shape
    # genuinely differs (a URL list from already-discovered endpoints, not a
    # repo-path checkout), but api_scan.py's Active API Scanning route has
    # actually executed it unconditionally since #72 shipped. Defaulting its
    # api_scan surface off here would be the opposite bug this test guards
    # against, a silent, retroactive removal of coverage every existing
    # user already had. See default_usage_for's and
    # app.core.tool_usage.is_nuclei_enabled_for_api_scan's docstrings.
    for entry in TOOL_REGISTRY:
        if entry["tool"] in TOOL_COMMANDS:
            continue
        usage = default_usage_for(entry["tool"])
        if entry["tool"] == "nuclei":
            assert usage == {
                "on_demand_scan": False,
                "ci_pipeline": False,
                "api_scan": True,
                "pr_guardrail": False,
            }, "nuclei must default on for api_scan only; every other surface stays off"
            continue
        assert not any(usage[s] for s in USAGE_SURFACES), entry["tool"]


# --- Findings-page category derivation (tool_category et al.) -------------


@pytest.mark.parametrize("entry", TOOL_REGISTRY, ids=ALL_TOOLS)
def test_tool_category_matches_the_registry_entry(entry):
    assert tool_category(entry["tool"]) == entry["category"]


def test_tool_category_covers_finding_tool_values_outside_the_registry():
    # Real Finding.tool values that never go through TOOL_REGISTRY at all
    # (see tool_registry.py's own comment on _EXTRA_TOOL_CATEGORIES): nuclei
    # findings are persisted tool="api-scan", not "nuclei", and malicious-
    # package findings are persisted tool="osv-malware" by a path that
    # bypasses the registry entirely.
    assert tool_category("api-scan") == "API/DAST"
    assert tool_category("osv-malware") == "Malicious Package"


def test_tool_category_falls_back_to_other_for_an_unrecognized_tool():
    # Reachable in practice via POST /api/ingest/{target_id}, which accepts
    # any caller-supplied `tool` string from a CI pipeline's own upload.
    assert tool_category("some-external-ci-tool") == UNKNOWN_TOOL_CATEGORY


def test_tools_in_category_is_the_exact_reverse_of_tool_category():
    for entry in TOOL_REGISTRY:
        assert entry["tool"] in tools_in_category(entry["category"])
    for cat in all_categories():
        for t in tools_in_category(cat):
            assert tool_category(t) == cat


def test_all_known_tools_matches_every_non_other_tool_category():
    known = set(all_known_tools())
    assert known == {e["tool"] for e in TOOL_REGISTRY} | {"api-scan", "osv-malware"}
    for t in known:
        assert tool_category(t) != UNKNOWN_TOOL_CATEGORY


def test_all_categories_includes_other_and_every_registry_category():
    cats = all_categories()
    assert UNKNOWN_TOOL_CATEGORY in cats
    for entry in TOOL_REGISTRY:
        assert entry["category"] in cats
    # Sorted, stable order for a UI dropdown -- not required to look a
    # particular way, just not to silently reorder between requests.
    assert cats == sorted(cats)


@pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="bundled-tool execution is verified in the image by scripts/verify_tools.py",
)
def test_bundled_tool_check_agrees_with_the_environment_when_tools_are_present():
    # A light smoke test for the local/dev case. The real assertion lives in
    # scripts/verify_tools.py, which runs in CI inside the built image where
    # every bundled tool is guaranteed to be installed.
    from app.api.tools.health import _check_one

    entry = next(e for e in TOOL_REGISTRY if e["tool"] == "semgrep")
    result = _check_one("semgrep", entry["version_cmd"])
    assert result["installed"] is True
