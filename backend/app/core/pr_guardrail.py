"""Core PR Guardrail diff logic (architecture doc Flow C / ROADMAP Sprint 2).

Kept dependency-free (no DB/HTTP) so the net-new diff logic is trivially
unit-testable: given a set of dedup hashes already Open on the target's
default branch, and a list of findings parsed off the PR's head branch,
return only the findings that are net-new.
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
