"""Core PR Guardrail diff logic (architecture doc Flow C / ROADMAP Sprint 2).

Kept dependency-free (no DB/HTTP) so the diff logic is trivially
unit-testable: given a set of dedup hashes already Open on the target's
default branch, and a list of findings parsed off the PR's head branch,
return only the findings that are net-new -- and, of those, only the ones
this PR's own changed lines actually introduced (``attributable_to_diff``).
"""

# Severities ordered from least to most severe; used to rank the "highest"
# severity among a set of net-new findings.
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

BLOCKING_SEVERITIES = {"Critical", "High"}


def compute_net_new(pr_findings: list[dict], existing_hashes: set[str]) -> list[dict]:
    """Return the subset of pr_findings whose dedup_hash is not already Open
    on the target's default branch.

    Each item in pr_findings is expected to carry a "dedup_hash" key (already
    computed by the caller via app.core.dedup.compute_dedup_hash) alongside
    whatever other finding fields it wants preserved (tool, rule_id, title,
    file_path, line_start, severity, ...).
    """
    return [f for f in pr_findings if f.get("dedup_hash") not in existing_hashes]


def highest_severity(findings: list[dict]) -> str | None:
    """Return the highest severity present among findings, or None if empty."""
    best = None
    best_rank = -1
    for f in findings:
        sev = f.get("severity")
        if sev is None:
            continue
        rank = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else -1
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best


def should_block(findings: list[dict], blocking_severities: set[str] | None = None) -> bool:
    """Blocking rule: any net-new finding at or above a blocking severity blocks
    the PR. Defaults to BLOCKING_SEVERITIES (Critical/High); callers with a
    workspace-level policy override (app.core.policy.apply_policies) can pass
    an explicit `blocking_severities` set instead."""
    severities = blocking_severities if blocking_severities is not None else BLOCKING_SEVERITIES
    return any(f.get("severity") in severities for f in findings)


# A file the PR touched whose changed lines could not be established -- a
# `patch` GitHub omits (binary blobs, a diff too large to inline), or a pure
# rename carrying no hunks. Mapped to this sentinel rather than to an empty
# set, because "we don't know which lines changed" must never be read as
# "no lines changed"; the first suppresses nothing, the second would
# suppress every finding in the file.
WHOLE_FILE = None


def _norm_path(path: str) -> str:
    """Repo-relative comparison form. Scanner output and GitHub's file list
    are both repo-relative already, but some tools prefix "./" and Windows
    checkouts report backslashes; neither should decide whether a finding is
    attributed to the author."""
    p = (path or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


# Distinct from WHOLE_FILE above: that means "in the diff, lines unknown",
# this means "not in the diff at all". A plain `None` default would collapse
# the two and turn every untouched file into an unconditional keep.
_UNTOUCHED = object()


def attributable_to_diff(findings: list[dict], changed_lines: dict[str, set[int] | None]) -> list[dict]:
    """Return the subset of ``findings`` this PR's own changes actually
    introduced.

    ``compute_net_new`` answers "is this finding absent from the default
    branch's last scan?", which is not the same question as "did this author
    write it?". Anything that shifts a dedup hash without anyone touching
    the code -- an upstream rule renamed under semgrep's ``--config=auto``, a
    scanner upgrade, a tool added to the PR surface but not the baseline
    scan, a stale baseline -- lands the repository's pre-existing findings on
    whichever PR is scanned next, pointing at files its author never opened.
    That is the failure this filter closes: net-new is necessary but not
    sufficient, and authorship is decided by the diff, not by hash equality.

    ``changed_lines`` maps a repo-relative path the PR adds or modifies to
    the set of line numbers it added/changed on the head side, or to
    ``WHOLE_FILE`` when those lines are unknown. A path absent from the map
    was not touched by this PR at all.

    Kept here, beside ``compute_net_new`` and equally dependency-free, so
    both halves of "what does this PR introduce" are unit-testable together.
    """
    lookup = {_norm_path(path): lines for path, lines in changed_lines.items()}
    kept = []
    for f in findings:
        added = lookup.get(_norm_path(f.get("file_path", "")), _UNTOUCHED)
        if added is _UNTOUCHED:
            continue
        if added is WHOLE_FILE:
            kept.append(f)
            continue
        start = f.get("line_start")
        if start is None:
            # No line to attribute (an SCA/license finding against a
            # manifest, say). The file itself is in the diff, so the change
            # is the author's; a dependency added in this PR is exactly the
            # case that must survive.
            kept.append(f)
            continue
        end = f.get("line_end") or start
        if end < start:
            end = start
        # A multi-line match counts if the PR touched any line of it: an
        # author who changed one argument of a five-line call introduced
        # what that call now does. Walked over the changed lines rather than
        # over the finding's range, so a tool reporting an absurd line_end
        # (a whole-file match, a malformed range) costs the size of the diff
        # instead of the size of the claim.
        if any(start <= line <= end for line in added):
            kept.append(f)
    return kept
