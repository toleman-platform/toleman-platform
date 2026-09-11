"""Autofix: generate a fix recommendation for a finding, and where possible
an actual patch -- as two deliberately separate steps, `suggest_fix` and
`open_fix_pr`, so generating a suggestion never itself writes to a repo.

`suggest_fix` always runs two independent things:

  * a plain-text recommendation -- AI-generated when a provider is
    configured (Admin > Global Integrations, same config app/api/ai.py
    already uses), deterministic per-finding-type guidance otherwise. This
    always returns *something*; it never raises.
  * an actual patch -- attempted only when one can be built on real file
    content. AI first (works uniformly across every finding type: SAST,
    SCA, secrets, IaC, ...) when a provider is configured; the
    OSV-backed dependency-version-bump app.core.fixability/remediation
    already compute is the deterministic fallback when no AI provider is
    configured (or the AI declines to produce a clean patch). A finding
    that fits neither path is recommendation-only -- this module never
    fabricates a diff it cannot back with a verified, unique match against
    the file as it actually exists in the repo.

Opening a PR is a second, explicit step (`open_fix_pr`, wired to
POST /{finding_id}/raise-pr): via the GitHub App's installation token
(mirrors app.core.pipeline_pr's branch+commit+PR flow), only when the App
is installed for the finding's target/workspace -- the caller (the API
layer) is responsible for falling back to showing the diff when it isn't.
Reading the *current* file content, to build a correct patch in
`suggest_fix`, goes through app.core.github_token.resolve_github_token,
which also accepts a plain PAT -- independent of whether the GitHub App is
installed, so a patch/diff can still be produced even when a PR cannot be
opened.

`open_fix_pr` doesn't care who or what produced `patch.new_content` -- it
just commits it. `raise-pr`/raise_fix_pr accepts any Patch regardless of
strategy, which is what lets an MCP client (see mcp-server/server.py) that
already holds the repo -- typically Claude Code -- read the flagged file
itself and generate the fix when `suggest_fix` came back with no diff (no
Toleman AI provider configured and no deterministic patch available), then
call raise_fix_pr with strategy="mcp_client" to still get a PR opened
through Toleman's installation token. See STRATEGY_LABELS for the full set
this labels in the PR body.
"""
import base64
import difflib
import json
import logging
import re
import time
from dataclasses import dataclass

import httpx
from sqlmodel import Session, select

from app.core.ai_provider import ai_configured, generate_text
from app.core.fixability import fixability_for_finding, fixed_version_summary
from app.core.github import github_get, repo_slug_from_url
from app.core.github_app import get_installation_token, resolve_config_for_installation, resolve_installation_for_repo
from app.core.github_token import resolve_github_token
from app.core.remediation import parse_version
from app.core.tool_registry import tool_category
from app.models.models import CveEnrichment, Finding, Target

logger = logging.getLogger(__name__)


class AutofixError(Exception):
    """A real infra failure opening the PR (GitHub API error, no App
    installed, etc). Callers catch this and fall back to returning the diff
    instead of failing the whole request -- a finding still gets its
    recommendation and its patch either way, just not a PR."""


@dataclass
class Patch:
    file_path: str
    old_content: str
    new_content: str
    ref: str  # branch the content was read from; also the PR base
    strategy: str  # "ai" | "deterministic_sca" | "mcp_client"
    explanation: str


# Labels the PR body under open_fix_pr uses to say how a patch was produced.
# "mcp_client" (issue #108 follow-up): an MCP client -- typically Claude Code,
# already holding the repo and able to read the flagged file directly -- read
# suggest_fix's recommendation, wrote the fix itself (no Toleman AI provider
# involved at all), and called raise_fix_pr with this strategy. Distinct from
# "ai", which means *Toleman's own* configured provider (app.core.ai_provider)
# generated the patch server-side.
STRATEGY_LABELS = {
    "ai": "an AI-generated",
    "deterministic_sca": "a deterministic dependency-upgrade",
    "mcp_client": "an MCP-client-generated",
}


def _strategy_label(strategy: str) -> str:
    return STRATEGY_LABELS.get(strategy, "a")


# ---------------------------------------------------------------------------
# Recommendation (always produced, never raises)
# ---------------------------------------------------------------------------

STATIC_GUIDANCE = {
    "Secrets": (
        "Rotate the exposed credential immediately (treat it as compromised), remove it from the file "
        "and from git history, and load it at runtime from an environment variable or a secrets manager "
        "instead of committing it to source."
    ),
    "IaC": (
        "Update the flagged resource's configuration to the secure setting the rule describes "
        "(least-privilege access, encryption at rest/in transit, or closing the open ingress rule), "
        "then re-run the scan to confirm it clears."
    ),
    "License": (
        "Replace the flagged dependency with one under a compatible license, or obtain a commercial "
        "license/exception for it, before shipping this code."
    ),
    "Malicious Package": (
        "Remove this dependency immediately -- it (or this version of it) has been identified as "
        "malicious, not merely vulnerable. Audit anywhere it was installed for signs of compromise."
    ),
}


def _recommendation_prompt(finding: Finding) -> str:
    return f"""You are a security engineer. Analyze this vulnerability finding and give a concise, actionable remediation.

Tool: {finding.tool}
Rule: {finding.rule_id}
Severity: {finding.severity}
Title: {finding.title}
File: {finding.file_path}{f':{finding.line_start}' if finding.line_start else ''}
Description: {finding.description}

Respond in under 150 words: what the risk is and the specific code/config fix."""


def _deterministic_recommendation(session: Session, finding: Finding) -> str:
    if finding.cve_id:
        verdict = fixability_for_finding(session, finding)
        if verdict == "fixable":
            row = session.exec(select(CveEnrichment).where(CveEnrichment.cve_id == finding.cve_id)).first()
            summary = fixed_version_summary(row)
            if summary:
                return f"Upgrade to {summary}. This resolves {finding.cve_id}."
        elif verdict == "no_known_fix":
            return (
                f"No fixed version has been published for {finding.cve_id} yet. Track the advisory for a "
                "fix, or mitigate (pin away from the vulnerable code path, add compensating controls) in "
                "the meantime."
            )
    category = tool_category(finding.tool)
    if category in STATIC_GUIDANCE:
        return STATIC_GUIDANCE[category]
    return (
        f"Review {finding.file_path}"
        + (f":{finding.line_start}" if finding.line_start else "")
        + f" against {finding.tool}'s rule `{finding.rule_id}` and apply the fix it describes. "
        "Configure an AI provider (Admin > Global Integrations) for a specific code-level suggestion here."
    )


def build_recommendation(session: Session, finding: Finding) -> str:
    """Always returns text; never raises. AI-generated when a provider is
    configured, deterministic (OSV fix data / tool-category guidance)
    otherwise or on AI failure."""
    if ai_configured(session):
        try:
            return generate_text(session, _recommendation_prompt(finding))
        except Exception:
            logger.warning(
                "autofix: AI recommendation failed for finding %s, falling back to deterministic text",
                finding.id, exc_info=True,
            )
    return _deterministic_recommendation(session, finding)


# ---------------------------------------------------------------------------
# Reading real file content (read path works with a PAT OR the GitHub App;
# writing a PR below requires the GitHub App specifically, same split as
# every other write in this codebase, see app.core.pr_guardrail_executor).
# ---------------------------------------------------------------------------


def _fetch_file(session: Session, target: Target, ref: str, path: str) -> tuple[str, str] | None:
    """(content, sha) for `path`@`ref` in target's repo, or None when it
    can't be read as text (missing, binary, or no usable credential)."""
    slug = repo_slug_from_url(target.repo_url)
    token = resolve_github_token(session, target.workspace_id, slug) or ""
    try:
        res = github_get(f"/repos/{slug}/contents/{path}", params={"ref": ref}, token=token)
    except httpx.HTTPError:
        logger.warning("autofix: error fetching %s@%s from %s", path, ref, slug, exc_info=True)
        return None
    if res.status_code != 200:
        return None
    data = res.json()
    if data.get("encoding") != "base64" or "content" not in data:
        return None
    try:
        content = base64.b64decode(data["content"]).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None  # binary file; nothing text-based to patch
    return content, data["sha"]


# ---------------------------------------------------------------------------
# AI patch: works uniformly across every finding type. The model only ever
# sees a small excerpt and must return the exact original snippet back;
# it's applied only when that snippet is a verified, unique match against
# the real file, so a hallucinated or ambiguous answer is dropped rather
# than guessed.
# ---------------------------------------------------------------------------

_CONTEXT_LINES = 40
_MAX_WINDOW_CHARS = 6000


def _file_window(content: str, line_start: int | None) -> str:
    lines = content.splitlines()
    if not line_start or line_start < 1 or line_start > len(lines):
        return content[:_MAX_WINDOW_CHARS]
    start = max(0, line_start - 1 - _CONTEXT_LINES)
    end = min(len(lines), line_start - 1 + _CONTEXT_LINES)
    numbered = [f"{i + 1}: {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)[:_MAX_WINDOW_CHARS]


def _patch_prompt(finding: Finding, window: str) -> str:
    return f"""You are a security engineer fixing a single vulnerability finding in place, in an existing file.

Tool: {finding.tool}
Rule: {finding.rule_id}
Severity: {finding.severity}
Title: {finding.title}
File: {finding.file_path}
Description: {finding.description}

Below is the relevant excerpt of {finding.file_path}. Line numbers are shown for your reference only --
do not include them in your answer.

{window}

Reply with STRICT JSON only, no markdown fences, no commentary, in exactly this shape:
{{"old_code": "<the exact original code to replace, verbatim including whitespace, copied from the excerpt above, with no line-number prefixes>", "new_code": "<the fixed replacement code>", "explanation": "<one sentence: what was wrong and what this changes>"}}

old_code must match a contiguous substring of the file exactly, or the patch cannot be applied. Keep the change minimal and scoped to this one finding. If you cannot produce a safe, minimal, exact-match fix, reply with {{"old_code": "", "new_code": "", "explanation": "no safe automated fix"}}."""


def _extract_json(text: str) -> dict | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except (json.JSONDecodeError, TypeError):
        return None


def _ai_patch(session: Session, finding: Finding, target: Target) -> Patch | None:
    ref = finding.branch or target.default_branch
    fetched = _fetch_file(session, target, ref, finding.file_path)
    if fetched is None:
        return None
    content, _sha = fetched
    window = _file_window(content, finding.line_start)
    try:
        raw = generate_text(session, _patch_prompt(finding, window), max_tokens=1500)
    except Exception:
        logger.warning("autofix: AI patch generation failed for finding %s", finding.id, exc_info=True)
        return None

    parsed = _extract_json(raw)
    if not parsed:
        return None
    old_code = parsed.get("old_code")
    new_code = parsed.get("new_code")
    explanation = parsed.get("explanation") or "AI-generated fix."
    if not old_code or new_code is None:
        return None
    if content.count(old_code) != 1:
        # Appears more than once (ambiguous) or not at all (hallucinated):
        # never guess which occurrence was meant.
        return None

    new_content = content.replace(old_code, new_code, 1)
    return Patch(
        file_path=finding.file_path,
        old_content=content,
        new_content=new_content,
        ref=ref,
        strategy="ai",
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# Deterministic SCA patch: no AI needed. Reuses the same OSV fixed-version
# data app.core.remediation/fixability already resolve, applied as a
# targeted version-bump against the small set of manifest formats where a
# plain-text substitution is safe (lockfiles are deliberately excluded --
# hand-editing a hash-bearing lockfile is how you get a corrupt install).
# ---------------------------------------------------------------------------


def _fuzzy_pkg_pattern(pkg: str) -> str:
    """Regex fragment matching `pkg` with -, _ and . treated as
    interchangeable, the same normalization PyPI itself applies to package
    names, so `my-pkg==1.0` still matches a lookup for `my_pkg`."""
    return "".join("[-_.]" if ch in "-_." else re.escape(ch) for ch in pkg)


def _bump_requirements_txt(content: str, package: str, new_version: str) -> tuple[str, str] | None:
    pattern = re.compile(
        rf"(?im)^([ \t]*{_fuzzy_pkg_pattern(package)}[ \t]*(?:==|>=|~=|<=)[ \t]*)([0-9][^\s#;]*)"
    )
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        return None
    m = matches[0]
    return m.group(0), f"{m.group(1)}{new_version}"


def _bump_package_json(content: str, package: str, new_version: str) -> tuple[str, str] | None:
    pattern = re.compile(rf'("{re.escape(package)}"\s*:\s*")(\^|~|>=)?([0-9][^"]*)(")')
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        return None
    m = matches[0]
    prefix = m.group(2) or ""
    return m.group(0), f"{m.group(1)}{prefix}{new_version}{m.group(4)}"


def _bump_go_mod(content: str, package: str, new_version: str) -> tuple[str, str] | None:
    # Matches both the single-line `require module v1.2.3` form and the
    # indented `\tmodule v1.2.3` line inside a `require (...)` block; the
    # optional "require " is captured into group(1) too, so it's preserved
    # (not silently dropped) in the rewritten line either way.
    pattern = re.compile(rf"(?m)^([ \t]*(?:require[ \t]+)?{re.escape(package)}[ \t]+)v?([0-9][^\s]*)")
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        return None
    m = matches[0]
    version = new_version if new_version.startswith("v") else f"v{new_version}"
    return m.group(0), f"{m.group(1)}{version}"


_MANIFEST_BUMPERS = {
    "requirements.txt": _bump_requirements_txt,
    "package.json": _bump_package_json,
    "go.mod": _bump_go_mod,
}


def _bumper_for_path(path: str):
    return _MANIFEST_BUMPERS.get(path.rsplit("/", 1)[-1])


def _sca_package_version(session: Session, finding: Finding) -> tuple[str, str] | None:
    """(package, version) for the smallest upgrade that clears this
    finding's CVE, same "lowest fix, never round up" rule as
    app.core.fixability.fixed_version_summary. None if there's no CVE, no
    resolved advisory, or no fix listed."""
    if not finding.cve_id:
        return None
    row = session.exec(select(CveEnrichment).where(CveEnrichment.cve_id == finding.cve_id)).first()
    if row is None or not row.fixed_versions:
        return None
    try:
        entries = json.loads(row.fixed_versions)
    except (TypeError, ValueError):
        return None
    if not entries:
        return None
    best = sorted(entries, key=lambda e: parse_version(str(e.get("fixed", ""))))[0]
    package, version = best.get("package"), best.get("fixed")
    if not package or not version:
        return None
    return str(package), str(version)


def _deterministic_sca_patch(session: Session, finding: Finding, target: Target) -> Patch | None:
    pkg_version = _sca_package_version(session, finding)
    if pkg_version is None:
        return None
    package, version = pkg_version
    bumper = _bumper_for_path(finding.file_path)
    if bumper is None:
        return None

    ref = finding.branch or target.default_branch
    fetched = _fetch_file(session, target, ref, finding.file_path)
    if fetched is None:
        return None
    content, _sha = fetched

    result = bumper(content, package, version)
    if result is None:
        return None
    old_str, new_str = result
    return Patch(
        file_path=finding.file_path,
        old_content=content,
        new_content=content.replace(old_str, new_str, 1),
        ref=ref,
        strategy="deterministic_sca",
        explanation=f"Upgrade {package} to {version}, resolving {finding.cve_id}.",
    )


def build_patch(session: Session, finding: Finding) -> Patch | None:
    """Best available patch for `finding`, or None when no automated fix
    could be generated -- not a failure, build_recommendation still returns
    text either way. AI first when configured (covers every finding type
    uniformly); the deterministic SCA version-bump is the no-AI fallback,
    and also the fallback if AI declines to produce a clean match."""
    target = session.get(Target, finding.target_id)
    if target is None:
        return None
    if ai_configured(session):
        patch = _ai_patch(session, finding, target)
        if patch is not None:
            return patch
    return _deterministic_sca_patch(session, finding, target)


def unified_diff(patch: Patch) -> str:
    return "".join(
        difflib.unified_diff(
            patch.old_content.splitlines(keepends=True),
            patch.new_content.splitlines(keepends=True),
            fromfile=f"a/{patch.file_path}",
            tofile=f"b/{patch.file_path}",
        )
    )


# ---------------------------------------------------------------------------
# Opening the fix as a real PR (GitHub App write path only, same split as
# every other write in this codebase -- see app.core.pipeline_pr).
# ---------------------------------------------------------------------------


def _installation_token_or_none(session: Session, target: Target) -> str | None:
    slug = repo_slug_from_url(target.repo_url)
    installation = resolve_installation_for_repo(session, target.workspace_id, slug)
    if not installation:
        return None
    config = resolve_config_for_installation(session, installation)
    if not config:
        return None
    try:
        return get_installation_token(config, installation.installation_id)
    except httpx.HTTPError:
        logger.warning("autofix: failed to mint installation token for repository", exc_info=True)
        return None


def open_fix_pr(session: Session, target: Target, finding: Finding, patch: Patch) -> dict:
    """Opens a PR with `patch` applied, branched off patch.ref (the same
    ref its content was read from) and targeting patch.ref as the PR base.
    Returns {"pr_url", "pr_number", "branch"}. Raises AutofixError (never a
    bare httpx exception) on any failure, so callers can fall back to
    returning the diff instead of failing the whole request."""
    slug = repo_slug_from_url(target.repo_url)
    token = _installation_token_or_none(session, target)
    if not token:
        raise AutofixError(
            "No GitHub App installation found for this target's workspace. "
            "Connect the GitHub App to open fix PRs automatically."
        )
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    ref_res = httpx.get(
        f"https://api.github.com/repos/{slug}/git/ref/heads/{patch.ref}", headers=headers, timeout=15
    )
    if ref_res.status_code != 200:
        raise AutofixError(
            f"failed to read branch '{patch.ref}' from GitHub: {ref_res.status_code} {ref_res.text[:200]}"
        )
    base_sha = ref_res.json()["object"]["sha"]

    branch_name = f"toleman/fix-finding-{finding.id}-{int(time.time())}"
    create_ref_res = httpx.post(
        f"https://api.github.com/repos/{slug}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        timeout=15,
    )
    if create_ref_res.status_code not in (200, 201):
        raise AutofixError(
            f"failed to create branch '{branch_name}': {create_ref_res.status_code} {create_ref_res.text[:200]}"
        )

    existing_res = httpx.get(
        f"https://api.github.com/repos/{slug}/contents/{patch.file_path}",
        headers=headers,
        params={"ref": patch.ref},
        timeout=15,
    )
    existing_sha = existing_res.json().get("sha") if existing_res.status_code == 200 else None

    content_b64 = base64.b64encode(patch.new_content.encode("utf-8")).decode("ascii")
    put_body = {"message": f"Fix: {finding.title}"[:250], "content": content_b64, "branch": branch_name}
    if existing_sha:
        put_body["sha"] = existing_sha
    put_res = httpx.put(
        f"https://api.github.com/repos/{slug}/contents/{patch.file_path}", headers=headers, json=put_body, timeout=15
    )
    if put_res.status_code not in (200, 201):
        raise AutofixError(
            f"failed to write {patch.file_path} on GitHub: {put_res.status_code} {put_res.text[:200]}"
        )

    strategy_label = _strategy_label(patch.strategy)
    pr_body = (
        f"Automated fix for finding #{finding.id}: **{finding.title}** "
        f"({finding.severity}, `{finding.tool}` / `{finding.rule_id}`).\n\n"
        f"{patch.explanation}\n\n"
        f"Opened automatically by Toleman's Autofix, via {strategy_label} patch. Review the diff before merging."
    )
    pr_res = httpx.post(
        f"https://api.github.com/repos/{slug}/pulls",
        headers=headers,
        json={"title": f"Fix: {finding.title}"[:250], "head": branch_name, "base": patch.ref, "body": pr_body},
        timeout=15,
    )
    if pr_res.status_code not in (200, 201):
        raise AutofixError(f"failed to open PR on GitHub: {pr_res.status_code} {pr_res.text[:300]}")

    pr = pr_res.json()
    return {"pr_url": pr["html_url"], "pr_number": pr["number"], "branch": branch_name}


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def suggest_fix(session: Session, finding: Finding) -> dict:
    """Recommendation + (if one could be built) a patch -- this never opens
    a PR. Raising a PR is a separate, explicit action (see open_fix_pr /
    the POST /{finding_id}/raise-pr endpoint), so a click on "Suggest fix"
    only ever generates something to look at, never writes to the repo.

    `new_content`/`ref`/`strategy`/`explanation` are the exact patch fields
    the caller must send back to /raise-pr verbatim: nothing here is cached
    server-side, so what's rendered as the diff is guaranteed to be what
    gets committed (no risk of an AI patch regenerating differently between
    "show me the fix" and "open the PR")."""
    recommendation = build_recommendation(session, finding)
    patch = build_patch(session, finding)
    if patch is None:
        return {
            "recommendation": recommendation,
            "strategy": None,
            "diff": None,
            "file_path": None,
            "new_content": None,
            "ref": None,
            "explanation": None,
        }
    return {
        "recommendation": recommendation,
        "strategy": patch.strategy,
        "diff": unified_diff(patch),
        "file_path": patch.file_path,
        "new_content": patch.new_content,
        "ref": patch.ref,
        "explanation": patch.explanation,
    }
