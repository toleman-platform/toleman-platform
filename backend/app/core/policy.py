"""Policy-as-code (ROADMAP Sprint 4): workspace-configurable severity/license
thresholds and org-level suppression rules layered on top of PR Guardrail's
default blocking behavior (app.core.pr_guardrail.BLOCKING_SEVERITIES).

Kept dependency-free (no DB/HTTP), same spirit as app.core.pr_guardrail, so
policy application is trivially unit-testable: given a list of net-new
findings and a list of active PolicyRule-shaped objects (or dicts) for the
target's workspace, return the filtered findings plus the effective set of
blocking severities.

If no relevant policy rules exist, callers should fall back to the default
`app.core.pr_guardrail.BLOCKING_SEVERITIES` -- policy rules are opt-in.
"""
from app.core.pr_guardrail import BLOCKING_SEVERITIES, SEVERITY_ORDER

# Local aliases so this module doesn't need to import the SQLModel enum
# (keeps it usable with plain dicts in tests).
BLOCK_SEVERITY = "block_severity"
SUPPRESS_RULE = "suppress_rule"
SUPPRESS_LICENSE = "suppress_license"


def _rule_type(rule) -> str:
    rt = rule.rule_type if hasattr(rule, "rule_type") else rule["rule_type"]
    return rt.value if hasattr(rt, "value") else rt


def _value(rule) -> str:
    return rule.value if hasattr(rule, "value") else rule["value"]


def _is_active(rule) -> bool:
    active = rule.active if hasattr(rule, "active") else rule.get("active", True)
    return bool(active)


def _matches_suppress_rule(finding: dict, value: str) -> bool:
    rule_id = finding.get("rule_id") or ""
    if not value or not rule_id:
        return False
    return value == rule_id or value in rule_id or rule_id in value


def _matches_suppress_license(finding: dict, value: str) -> bool:
    if not value:
        return False
    value_lower = value.lower()
    rule_id = (finding.get("rule_id") or "").lower()
    title = (finding.get("title") or "").lower()
    if rule_id == f"license:{value_lower}":
        return True
    if rule_id.startswith("license:") and value_lower in rule_id:
        return True
    return value_lower in title and "license" in (rule_id or title)


def effective_blocking_severities(policies: list) -> set[str]:
    """Return the effective blocking-severity set for a workspace: the union
    of default BLOCKING_SEVERITIES escalated by the lowest-ranked active
    BLOCK_SEVERITY policy (e.g. a BLOCK_SEVERITY=Medium policy means
    Medium/High/Critical all block). Falls back to the default set unchanged
    if no active BLOCK_SEVERITY policy exists for the workspace."""
    thresholds = [
        _value(r)
        for r in policies
        if _is_active(r) and _rule_type(r) == BLOCK_SEVERITY and _value(r) in SEVERITY_ORDER
    ]
    if not thresholds:
        return set(BLOCKING_SEVERITIES)

    lowest_rank = min(SEVERITY_ORDER.index(t) for t in thresholds)
    return set(SEVERITY_ORDER[lowest_rank:])


def apply_policies(net_new: list[dict], policies: list) -> tuple[list[dict], set[str]]:
    """Apply a workspace's active policy rules to a list of net-new findings.

    Returns (filtered_findings, effective_blocking_severities):
      - filtered_findings: net_new with any finding matching an active
        SUPPRESS_RULE or SUPPRESS_LICENSE policy removed.
      - effective_blocking_severities: the workspace's active BLOCK_SEVERITY
        policy threshold expanded to a set, or the default BLOCKING_SEVERITIES
        if no such policy is configured.
    """
    suppress_rule_values = [_value(r) for r in policies if _is_active(r) and _rule_type(r) == SUPPRESS_RULE]
    suppress_license_values = [_value(r) for r in policies if _is_active(r) and _rule_type(r) == SUPPRESS_LICENSE]

    filtered = []
    for f in net_new:
        if any(_matches_suppress_rule(f, v) for v in suppress_rule_values):
            continue
        if any(_matches_suppress_license(f, v) for v in suppress_license_values):
            continue
        filtered.append(f)

    return filtered, effective_blocking_severities(policies)
