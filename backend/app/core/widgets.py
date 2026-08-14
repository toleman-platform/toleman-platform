"""Configurable-dashboard widget catalog + real data resolvers (issue #69).

Deliberately ~6 concrete, real widgets backed by real queries -- NOT a
generic "arbitrary chart config" system. Adding a new widget type later
means adding one entry to WIDGET_CATALOG plus one resolver function here,
not a rewrite -- mirrors the "one entry + one file" extensibility
documented in ARCHITECTURE.md for the admin page's tabs. `security_score`
below is exactly that: #63's composite score, added after #69 shipped.

Every resolver has the signature (session, ws_ids, config) -> JSON-able dict,
where ws_ids is the caller's accessible_workspace_ids() result (None for
admins). Resolvers reuse the same query shapes already established in
app/api/dashboard.py and app/api/findings.py rather than duplicating scoping
logic ad hoc.
"""
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlmodel import Session, func, select

from app.core.fp_learning import AUTO_SUPPRESS_REASON_PREFIX
from app.core.security_score import compute_security_score, resolve_target_ids_for_scope
from app.core.sla import compute_sla_status
from app.models.models import Finding, FindingState, Severity, Target

WidgetResolver = Callable[[Session, "list[int] | None", dict], Any]

# Findings still counted as "open" for KPI/trend/ranking purposes -- mirrors
# app.core.sla.CLOSED_STATES's complement (Reopened still counts as open).
OPEN_STATES = (FindingState.OPEN, FindingState.REOPENED)


def _scoped_targets(session: Session, ws_ids: "list[int] | None") -> list[Target]:
    query = select(Target)
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    return list(session.exec(query).all())


def _scoped_findings_query(ws_ids: "list[int] | None"):
    query = select(Finding)
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    return query


def _target_names(session: Session, target_ids: set[int]) -> dict[int, str]:
    if not target_ids:
        return {}
    rows = session.exec(select(Target).where(Target.id.in_(target_ids))).all()
    return {t.id: t.name for t in rows}


# ---------------------------------------------------------------------------
# Widget resolvers
# ---------------------------------------------------------------------------


def resolve_kpi_cards(session: Session, ws_ids, config: dict) -> dict:
    """Open / critical / high / mitigated counts + targets onboarded --
    reuses the same counting logic as GET /api/dashboard/summary and
    /stats, just returned as one bundle for the KPI-cards widget."""
    targets = _scoped_targets(session, ws_ids)
    findings = list(session.exec(_scoped_findings_query(ws_ids)).all())
    open_findings = [f for f in findings if f.state in OPEN_STATES]
    critical = sum(1 for f in open_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in open_findings if f.severity == Severity.HIGH)
    mitigated = sum(1 for f in findings if f.state == FindingState.MITIGATED)
    return {
        "open": len(open_findings),
        "critical": critical,
        "high": high,
        "mitigated": mitigated,
        "targets": len(targets),
    }


def resolve_findings_trend(session: Session, ws_ids, config: dict) -> dict:
    """Real daily snapshot of open-findings count over the last N days
    (config: `days`, default 14, clamped 1-90).

    A "grouped by week from first_seen/state transitions" trend was the
    first idea, but this platform's real seeded finding history only spans
    about a day (first_seen ranges from 2026-08-12 16:00 to 2026-08-13
    15:08 at the time this was written -- checked live against Postgres,
    not assumed) -- grouping that into weekly buckets would render a
    single, meaningless bar. Reconstructing a real *daily* open-count
    snapshot (as of the end of each day, from real first_seen/mitigated_at
    timestamps) is honest with sparse history today and still correct once
    real history accumulates.
    """
    days = max(1, min(int(config.get("days", 14)), 90))
    findings = list(session.exec(_scoped_findings_query(ws_ids)).all())
    today = datetime.utcnow().date()
    points = []
    for i in range(days - 1, -1, -1):
        day = today - timedelta(days=i)
        open_count = sum(
            1
            for f in findings
            if f.first_seen.date() <= day and (f.mitigated_at is None or f.mitigated_at.date() > day)
        )
        points.append({"date": day.isoformat(), "open": open_count})
    return {"points": points}


def resolve_cve_timeline(session: Session, ws_ids, config: dict) -> dict:
    """Real Trivy findings carrying a cve_id, most recent first, org-wide
    (subject to the caller's workspace scoping). config: `limit` (default
    15, clamped 1-100)."""
    limit = max(1, min(int(config.get("limit", 15)), 100))
    query = (
        _scoped_findings_query(ws_ids)
        .where(Finding.cve_id.is_not(None))
        .order_by(Finding.first_seen.desc())
        .limit(limit)
    )
    findings = list(session.exec(query).all())
    names = _target_names(session, {f.target_id for f in findings})
    items = [
        {
            "finding_id": f.id,
            "cve_id": f.cve_id,
            "title": f.title,
            "severity": f.severity,
            "state": f.state,
            "target_id": f.target_id,
            "target_name": names.get(f.target_id),
            "first_seen": f.first_seen.isoformat(),
            "epss_score": f.epss_score,
            "kev_listed": f.kev_listed,
        }
        for f in findings
    ]
    return {"items": items}


def resolve_sla_compliance(session: Session, ws_ids, config: dict) -> dict:
    """Same aggregate as GET /api/dashboard/sla-compliance (#70), computed
    query-time via app.core.sla.compute_sla_status."""
    query = select(Finding).where(Finding.state.in_(OPEN_STATES))
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    open_findings = session.exec(query).all()

    with_sla = 0
    in_violation = 0
    for f in open_findings:
        sla_days, violated = compute_sla_status(session, f)
        if sla_days is None:
            continue
        with_sla += 1
        if violated:
            in_violation += 1
    return {"with_sla": with_sla, "in_violation": in_violation, "compliant": with_sla - in_violation}


def resolve_top_risky_repos(session: Session, ws_ids, config: dict) -> dict:
    """Targets ranked by open critical/high count, tie-broken by summed
    priority_score (app.core.scoring) -- config: `limit` (default 5,
    clamped 1-50)."""
    limit = max(1, min(int(config.get("limit", 5)), 50))
    targets = _scoped_targets(session, ws_ids)
    items = []
    for t in targets:
        rows = session.exec(
            select(Finding.severity, func.count(), func.sum(Finding.priority_score))
            .where(Finding.target_id == t.id, Finding.state.in_(OPEN_STATES))
            .group_by(Finding.severity)
        ).all()
        critical = high = 0
        priority_sum = 0
        for severity, count, score_sum in rows:
            if severity == Severity.CRITICAL:
                critical = count
            elif severity == Severity.HIGH:
                high = count
            priority_sum += int(score_sum or 0)
        items.append(
            {
                "target_id": t.id,
                "target_name": t.name,
                "critical": critical,
                "high": high,
                "priority_score_sum": priority_sum,
            }
        )
    items.sort(key=lambda r: (r["critical"], r["high"], r["priority_score_sum"]), reverse=True)
    return {"items": items[:limit]}


def resolve_recent_findings(session: Session, ws_ids, config: dict) -> dict:
    """Most recently first-seen findings, org-wide -- config: `limit`
    (default 10, clamped 1-100). Reuses app.core.sla.compute_sla_status the
    same way GET /api/findings does.

    Issue #119: a UX audit flagged 4 visually-identical rows in this widget.
    Checked live against Postgres -- there was zero real duplication (no
    repeated `dedup_hash`, distinct `id`s, `SELECT dedup_hash, count(*) ...
    HAVING count(*) > 1` returned 0 rows across all findings): a single scan
    can legitimately trigger the same rule (e.g. Semgrep's
    django-no-csrf-token) across several template files within milliseconds
    of each other, and the old payload here (title/severity/tool/target/
    date-only first_seen) had no field that differed between those rows.
    `file_path` is added below so the frontend can render the one thing
    that actually distinguishes them, instead of a client-side dedup hack
    papering over data that was never duplicated.
    """
    limit = max(1, min(int(config.get("limit", 10)), 100))
    query = _scoped_findings_query(ws_ids).order_by(Finding.first_seen.desc()).limit(limit)
    findings = list(session.exec(query).all())
    names = _target_names(session, {f.target_id for f in findings})
    items = []
    for f in findings:
        sla_days, sla_violated = compute_sla_status(session, f)
        items.append(
            {
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "state": f.state,
                "tool": f.tool,
                "target_id": f.target_id,
                "target_name": names.get(f.target_id),
                "file_path": f.file_path,
                "first_seen": f.first_seen.isoformat(),
                "sla_days": sla_days,
                "sla_violated": sla_violated,
            }
        )
    return {"items": items}


def resolve_security_score(session: Session, ws_ids, config: dict) -> dict:
    """Composite security health score (issue #63) -- same
    app.core.security_score.compute_security_score used by the standalone
    GET /api/dashboard/security-score endpoint, so the widget and the
    dedicated endpoint always agree for the same scope. config:
    `target_id`/`group_id` (both optional, mutually exclusive -- neither
    means org-wide), matching #61's group_id filtering convention. The
    "Security Score" widget itself always resolves org-wide (its
    default_config is {}); a scoped view is a client-side-only
    interaction in the widget's own component (frontend/src/components/
    dashboard/widgets.tsx's SecurityScoreWidget), which calls
    GET /api/dashboard/security-score directly rather than round-tripping
    through a saved per-instance widget config -- there's no config-editing
    UI in this dashboard yet (see DashboardBoard), so a fixed
    scope-per-saved-widget-instance wouldn't give real drill-down anyway."""
    target_id = config.get("target_id")
    group_id = config.get("group_id")
    target_ids = resolve_target_ids_for_scope(session, ws_ids, target_id, group_id)
    return compute_security_score(session, target_ids)


def resolve_fp_auto_suppressions(session: Session, ws_ids, config: dict) -> dict:
    """"X findings auto-suppressed this month" (issue #76). Counts real
    Finding rows the false-positive learning engine set to FALSE_POSITIVE at
    ingestion time this calendar month -- identified by
    app.core.fp_learning.AUTO_SUPPRESS_REASON_PREFIX stamped onto
    Finding.state_reason by apply_auto_suppression, not a separate event-log
    table (see FalsePositiveRule's docstring for why). first_seen is used as
    the "when" -- an auto-suppressed finding is marked FALSE_POSITIVE at the
    moment it's first created, so first_seen and the suppression both happen
    in the same instant."""
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    query = _scoped_findings_query(ws_ids).where(
        Finding.state == FindingState.FALSE_POSITIVE,
        Finding.state_reason.like(f"{AUTO_SUPPRESS_REASON_PREFIX}%"),
        Finding.first_seen >= month_start,
    )
    count = len(list(session.exec(query).all()))
    return {"count": count, "since": month_start.date().isoformat()}


WIDGET_CATALOG: dict[str, dict[str, Any]] = {
    "kpi_cards": {
        "name": "KPI Cards",
        "description": "Open / critical / high / mitigated counts and targets onboarded.",
        "resolver": resolve_kpi_cards,
        "default_config": {},
    },
    "findings_trend": {
        "name": "Findings Over Time",
        "description": "Daily snapshot of open findings over the last N days.",
        "resolver": resolve_findings_trend,
        "default_config": {"days": 14},
    },
    "cve_timeline": {
        "name": "CVE Timeline",
        "description": "Most recent CVEs affecting your packages org-wide, from real Trivy findings.",
        "resolver": resolve_cve_timeline,
        "default_config": {"limit": 15},
    },
    "sla_compliance": {
        "name": "SLA Compliance",
        "description": "Open findings within vs. past their SLA window.",
        "resolver": resolve_sla_compliance,
        "default_config": {},
    },
    "top_risky_repos": {
        "name": "Top Risky Repos",
        "description": "Targets ranked by open critical/high findings.",
        "resolver": resolve_top_risky_repos,
        "default_config": {"limit": 5},
    },
    "recent_findings": {
        "name": "Recent Findings",
        "description": "Most recently discovered findings, org-wide.",
        "resolver": resolve_recent_findings,
        "default_config": {"limit": 10},
    },
    "security_score": {
        "name": "Security Score",
        "description": "Composite 0-100 health score + letter grade (open findings, SLA compliance, scan coverage, FP rate, trend).",
        "resolver": resolve_security_score,
        "default_config": {},
    },
    "fp_auto_suppressions": {
        "name": "Auto-Suppressed Findings",
        "description": "Findings auto-suppressed this month by learned false-positive rules (issue #76).",
        "resolver": resolve_fp_auto_suppressions,
        "default_config": {},
    },
}

# Sensible out-of-the-box composition for a user with no saved
# DashboardLayout row yet. Order mirrors the previous fixed dashboard
# (frontend/(dashboard)/page.tsx pre-#69) reasonably closely. security_score
# leads the list (#63) -- a CISO/CTO's single-number read on posture belongs
# above the granular KPI breakdown, not after it.
DEFAULT_WIDGET_ORDER = [
    "security_score",
    "kpi_cards",
    "sla_compliance",
    "findings_trend",
    "top_risky_repos",
    "cve_timeline",
    "recent_findings",
]


def build_default_layout() -> list[dict]:
    """Deliberately deterministic instance ids (`default-<widget_id>`, not
    uuid4) -- this is regenerated on every call for a user with no saved
    DashboardLayout row (both GET /layout and GET /widget-data call it
    independently), so a random id here would make the two responses'
    instance ids disagree and break the frontend's data[widget.id] lookup
    before the user has ever saved anything. Once a user saves a layout,
    their real DashboardLayout.widgets row (with frontend-generated
    crypto.randomUUID() ids) is used instead and this function isn't
    consulted again for them.
    """
    return [
        {"id": f"default-{wid}", "widget_id": wid, "config": dict(WIDGET_CATALOG[wid]["default_config"])}
        for wid in DEFAULT_WIDGET_ORDER
    ]
