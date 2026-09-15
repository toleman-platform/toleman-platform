"""Configurable-dashboard widget catalog + real data resolvers (issue #69).

Deliberately ~6 concrete, real widgets backed by real queries; NOT a
generic "arbitrary chart config" system. Adding a new widget type later
means adding one entry to WIDGET_CATALOG plus one resolver function here,
not a rewrite; mirrors the "one entry + one file" extensibility
documented in ARCHITECTURE.md for the admin page's tabs. `security_score`
below is exactly that: #63's composite score, added after #69 shipped.

Every resolver has the signature (session, ws_ids, config) -> JSON-able dict,
where ws_ids is the caller's accessible_workspace_ids() result (None for
admins). Resolvers reuse the same query shapes already established in
app/api/dashboard.py and app/api/findings.py rather than duplicating scoping
logic ad hoc.
"""
from datetime import timedelta
from typing import Any, Callable

from sqlmodel import Session, func, select

from app.core.fp_learning import AUTO_SUPPRESS_REASON_PREFIX
from app.core.security_score import compute_security_score, resolve_target_ids_for_scope
from app.core.sla import compute_sla_status
from app.core import target_lifecycle
from app.core.time import utcnow
from app.core.tool_registry import tools_in_category
from app.models.models import Finding, FindingState, OPEN_FINDING_STATES as OPEN_STATES, Severity, Target

WidgetResolver = Callable[[Session, "list[int] | None", dict], Any]

# Findings still counted as "open" for KPI/trend/ranking purposes, mirrors
# app.core.sla.CLOSED_STATES's complement (Reopened still counts as open).
# (Imported as OPEN_FINDING_STATES from app.models.models above.)


def _scoped_targets(session: Session, ws_ids: "list[int] | None") -> list[Target]:
    # (#273) Soft-deleted targets are excluded from every widget: a deleted
    # repo must not keep inflating "targets onboarded", nor appear in a
    # top-risk ranking.
    query = target_lifecycle.live_targets(select(Target))
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    return list(session.exec(query).all())


def _scoped_findings_query(ws_ids: "list[int] | None"):
    # (#273) The soft-delete filter is a subquery, not an extra condition on
    # the workspace join below -- that join only happens for non-admin
    # callers, so an admin's KPI cards and trend charts would otherwise keep
    # counting findings belonging to deleted targets.
    query = target_lifecycle.exclude_deleted_targets(select(Finding), Finding.target_id)
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    return query


def _target_names(session: Session, target_ids: set[int]) -> dict[int, str]:
    if not target_ids:
        return {}
    # (#273) Live only. The ids handed in here come from findings that have
    # already been filtered, so a deleted target should never reach this --
    # filtering anyway means a ranking widget degrades to omitting a row
    # rather than naming a repo the reader was told no longer exists.
    rows = session.exec(target_lifecycle.live_targets(select(Target)).where(Target.id.in_(target_ids))).all()
    return {t.id: t.name for t in rows}


# ---------------------------------------------------------------------------
# Widget resolvers
# ---------------------------------------------------------------------------


def resolve_kpi_cards(session: Session, ws_ids, config: dict) -> dict:
    """Open / critical / high / mitigated vulnerability counts + targets
    onboarded; reuses the same counting logic as GET /api/dashboard/summary
    and /stats, just returned as one bundle for the KPI-cards widget.

    License findings are excluded, which is what those two endpoints (and
    /posture, /sla-compliance, the targets summary and the security score)
    have done since #425; this resolver was the one posture surface that
    never got the filter. The disagreement was visible on a single screen:
    the card read "188 Open Findings" on a workspace whose own Findings page
    put 40 in the needs-action queue and 148 under Licence review, and the
    card's own link (`/findings?state=Open`) lands on that 40-row queue. A
    copyleft licence on a transitive dependency is a quarterly policy call,
    not something open on the security team.

    `license_open` reports what was left out, so the smaller number stays
    reconcilable against the Findings page rather than looking like findings
    went missing.
    """
    targets = _scoped_targets(session, ws_ids)
    findings = list(session.exec(_scoped_findings_query(ws_ids)).all())
    # NOT IN the License tools rather than IN `vulnerability_tools()`, for
    # the reason spelled out at length in resolve_needs_action_queue: an
    # "Other"-category tool (any `tool` string a CI pipeline invents when it
    # POSTs SARIF to /api/ingest) is in neither set, and an IN-list would
    # silently drop its findings from this count while the Findings page
    # this card links to still lists them.
    license_tools = set(tools_in_category("License"))
    vulnerabilities = [f for f in findings if f.tool not in license_tools]
    open_findings = [f for f in vulnerabilities if f.state in OPEN_STATES]
    critical = sum(1 for f in open_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in open_findings if f.severity == Severity.HIGH)
    mitigated = sum(1 for f in vulnerabilities if f.state == FindingState.MITIGATED)
    license_open = sum(1 for f in findings if f.tool in license_tools and f.state in OPEN_STATES)
    return {
        "open": len(open_findings),
        "critical": critical,
        "high": high,
        "mitigated": mitigated,
        "targets": len(targets),
        "license_open": license_open,
    }


def resolve_findings_trend(session: Session, ws_ids, config: dict) -> dict:
    """Real daily snapshot of open-findings count over the last N days
    (config: `days`, default 14, clamped 1-90).

    A "grouped by week from first_seen/state transitions" trend was the
    first idea, but this platform's real seeded finding history only spans
    about a day (first_seen ranges from 2026-08-12 16:00 to 2026-08-13
    15:08 at the time this was written, checked live against Postgres,
    not assumed); grouping that into weekly buckets would render a
    single, meaningless bar. Reconstructing a real *daily* open-count
    snapshot (as of the end of each day, from real first_seen/mitigated_at
    timestamps) is honest with sparse history today and still correct once
    real history accumulates.
    """
    days = max(1, min(int(config.get("days", 14)), 90))
    # Vulnerabilities only, the same exclusion the KPI cards and the security
    # score apply. This chart sits directly beneath a card reading "188 Open
    # Findings" that had already dropped licence findings, so counting them
    # here made the trend line and the counter above it disagree by the whole
    # licence population -- 190 against 40 on a real instance. NOT IN the
    # licence tools rather than IN vulnerability_tools(), so a tool name a CI
    # pipeline invents when it POSTs SARIF stays in scope.
    findings = list(
        session.exec(
            _scoped_findings_query(ws_ids).where(Finding.tool.not_in(tools_in_category("License")))
        ).all()
    )
    today = utcnow().date()
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
    query-time via app.core.sla.compute_sla_status.

    Including the licence exclusion, which is what made "same aggregate"
    true: SlaRule is keyed purely on severity with no category awareness, so
    a workspace's "High: fix within 30 days" rule applies just as literally
    to a copyleft licence a scanner graded High as to an exploitable
    finding. Nobody fixes a licence on a days-to-fix clock. Both the
    endpoint and security_score._sla_score already excluded them; this
    resolver did not, so the same dashboard could report two different SLA
    figures.
    """
    query = select(Finding).where(
        Finding.state.in_(OPEN_STATES), Finding.tool.not_in(tools_in_category("License"))
    )
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
    priority_score (app.core.scoring), config: `limit` (default 5,
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


def resolve_needs_action_queue(session: Session, ws_ids, config: dict) -> dict:
    """Top of the "Needs action" queue -- the same grouped view GET
    /api/findings/groups renders on the Findings page, with that page's own
    "Needs action" tab filters applied (frontend/src/lib/findings-view.ts's
    `queueFilters("action")`: open states only, License excluded), capped to
    `limit` rows (default 5, clamped 1-25) in that same default
    ("exploitability" -- highest priority score first) order.

    This widget (catalog id `recent_findings`, kept for backward
    compatibility with already-saved DashboardLayout rows) used to be
    literally that: the N most-recently-first-seen findings, unfiltered by
    triage state or category. Observed live on a real instance, that
    rendered ten rows of which four were the identical Semgrep suggestion
    to use `QUERY.count()` instead of `len(QUERY.all())`, and three more
    were "logger call with a potential hardcoded secret" firing on log
    FORMAT STRINGS containing no secret (e.g. "Purged expired GitHub token
    for workspace %s") -- while the Findings page's own "Needs action" queue
    reported a single finding actually needing attention, and none of the
    ten rows showed their triage state, so an already-mitigated finding
    looked exactly like an open one. The single most-visible strip on the
    landing page was spending itself on one noisy lint rule instead of the
    one thing a reader actually had to act on.

    Built on app.core.grouping's group key/aggregate/representative-
    selection primitives (the same ones GET /api/findings/groups is built
    on) rather than re-deriving that logic by hand, so this cannot quietly
    drift from what the real queue would show for the same filters --
    imported from app.api.findings itself is deliberately avoided, since
    that is the API layer importing back into core would invert. `state` on
    each item is the *representative* member's (always "Open" or
    "Reopened": every member here already passed the open-states filter
    below, so it is never a resolved state) -- never synthesized across a
    group's members, the same conservative rule app.core.grouping already
    applies to SLA/fixability (see `representative_finding`'s docstring).
    """
    from app.core.grouping import (
        UNGROUPED_CATEGORIES,
        group_aggregate_columns,
        representative_finding,
        severity_for_weight,
    )
    from app.core.tool_registry import tool_category, tools_in_category

    limit = max(1, min(int(config.get("limit", 5)), 25))

    # Same open-states + category exclusion as queueFilters("action"): a
    # copyleft license on a transitive dependency is a quarterly policy call,
    # not an incident, and a resolved/accepted/false-positive/won't-fix
    # finding is, by definition, not something left to do -- letting either
    # kind sit in a strip a reader reasonably reads as a to-do is exactly
    # the bug this resolver exists to fix.
    #
    # The exclusion is expressed the way the real queue expresses it -- NOT IN
    # the License tools -- rather than IN `vulnerability_tools()`, and the
    # difference is not cosmetic. `vulnerability_tools()` is derived from
    # `all_known_tools()`, which by design contains only tools present in
    # TOOL_REGISTRY; an "Other"-category tool (any `tool` string a CI pipeline
    # invents when it POSTs SARIF to /api/ingest/{target_id}) is therefore in
    # neither set. Filtering by IN would silently drop those findings from this
    # widget while GET /api/findings/groups?queue=action still lists them,
    # because _apply_category excludes only the License category -- so a
    # custom scanner's Critical would top the Findings page and be absent from
    # the dashboard, which is precisely the disagreement this resolver exists
    # to end. NOT IN keeps unrecognised tools in scope, and a newly integrated
    # scanner lands here by default rather than going missing.
    base = _scoped_findings_query(ws_ids).where(
        Finding.state.in_(OPEN_STATES), Finding.tool.not_in(tools_in_category("License"))
    )

    ungrouped_tools: set[str] = set()
    for category in UNGROUPED_CATEGORIES:
        ungrouped_tools.update(tools_in_category(category))

    stubs: list[dict] = []

    # --- the collapsible majority: one row per (tool, rule_id) decision ---
    grouped_query = base
    if ungrouped_tools:
        grouped_query = grouped_query.where(Finding.tool.not_in(ungrouped_tools))
    # `execute`, not `exec`: see the identical comment in
    # app/api/findings.py's list_finding_groups -- the aggregate row needs
    # to come back as a labelled Row, not unwrapped to its first column.
    rows = session.execute(
        grouped_query.with_only_columns(*group_aggregate_columns())
        .group_by(Finding.tool, Finding.rule_id)
        .order_by(func.max(Finding.priority_score).desc(), Finding.tool, Finding.rule_id)
        .limit(limit)
    ).all()
    for row in rows:
        stubs.append(
            {
                "tool": row.tool,
                "rule_id": row.rule_id,
                "grouped": True,
                "finding": None,
                "severity": severity_for_weight(row.severity_weight or 0),
                "finding_count": row.finding_count,
                "max_priority_score": row.max_priority_score or 0,
            }
        )

    # --- the deliberately ungrouped: Secrets/Malicious Package, one row each --
    # (one leaked credential is one incident, not an instance of a gitleaks
    # rule; see app.core.grouping's module docstring for why these never
    # collapse into each other.)
    if ungrouped_tools:
        singles = list(
            session.exec(
                base.where(Finding.tool.in_(ungrouped_tools))
                .order_by(Finding.priority_score.desc(), Finding.id)
                .limit(limit)
            ).all()
        )
        for f in singles:
            stubs.append(
                {
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "grouped": False,
                    "finding": f,
                    "severity": getattr(f.severity, "value", f.severity),
                    "finding_count": 1,
                    "max_priority_score": f.priority_score,
                }
            )

    # Same default ("exploitability") tiebreak _sort_groups uses: highest
    # priority score, then largest blast radius. Both halves above are
    # already internally ordered and deterministic, so Python's stable sort
    # keeps that ordering within ties instead of falling through to
    # whatever order the database happened to return.
    stubs.sort(key=lambda g: (g["max_priority_score"], g["finding_count"]), reverse=True)
    stubs = stubs[:limit]

    items: list[dict] = []
    for stub in stubs:
        rep = stub["finding"]
        if rep is None:
            # Scoped to `grouped_query`, never a bare select over the table --
            # see the identical concern in list_finding_groups: a
            # representative picked outside the caller's own filtered query
            # could be a finding this caller isn't entitled to see.
            rep = representative_finding(
                session, grouped_query.where(Finding.tool == stub["tool"], Finding.rule_id == stub["rule_id"])
            )
            if rep is None:
                continue
        sla_days, sla_violated = compute_sla_status(session, rep)
        items.append(
            {
                "tool": stub["tool"],
                "rule_id": stub["rule_id"],
                "category": tool_category(stub["tool"]),
                "title": rep.title,
                "severity": stub["severity"],
                "state": rep.state,
                "grouped": stub["grouped"],
                "finding_count": stub["finding_count"],
                "representative_id": rep.id,
                "representative_target_id": rep.target_id,
                "representative_file_path": rep.file_path,
                "first_seen": rep.first_seen.isoformat(),
                "sla_days": sla_days,
                "sla_violated": sla_violated,
            }
        )

    names = _target_names(session, {i["representative_target_id"] for i in items})
    for item in items:
        item["target_name"] = names.get(item["representative_target_id"])

    return {"items": items}


def resolve_security_score(session: Session, ws_ids, config: dict) -> dict:
    """Composite security health score (issue #63), same
    app.core.security_score.compute_security_score used by the standalone
    GET /api/dashboard/security-score endpoint, so the widget and the
    dedicated endpoint always agree for the same scope. config:
    `target_id`/`group_id` (both optional, mutually exclusive; neither
    means org-wide), matching #61's group_id filtering convention. The
    "Security Score" widget itself always resolves org-wide (its
    default_config is {}); a scoped view is a client-side-only
    interaction in the widget's own component (frontend/src/components/
    dashboard/widgets.tsx's SecurityScoreWidget), which calls
    GET /api/dashboard/security-score directly rather than round-tripping
    through a saved per-instance widget config; there's no config-editing
    UI in this dashboard yet (see DashboardBoard), so a fixed
    scope-per-saved-widget-instance wouldn't give real drill-down anyway."""
    target_id = config.get("target_id")
    group_id = config.get("group_id")
    target_ids = resolve_target_ids_for_scope(session, ws_ids, target_id, group_id)
    return compute_security_score(session, target_ids)


def resolve_fp_auto_suppressions(session: Session, ws_ids, config: dict) -> dict:
    """"X findings auto-suppressed this month" (issue #76). Counts real
    Finding rows the false-positive learning engine set to FALSE_POSITIVE at
    ingestion time this calendar month, identified by
    app.core.fp_learning.AUTO_SUPPRESS_REASON_PREFIX stamped onto
    Finding.state_reason by apply_auto_suppression, not a separate event-log
    table (see FalsePositiveRule's docstring for why). first_seen is used as
    the "when"; an auto-suppressed finding is marked FALSE_POSITIVE at the
    moment it's first created, so first_seen and the suppression both happen
    in the same instant."""
    month_start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    query = _scoped_findings_query(ws_ids).where(
        Finding.state == FindingState.FALSE_POSITIVE,
        Finding.state_reason.like(f"{AUTO_SUPPRESS_REASON_PREFIX}%"),
        Finding.first_seen >= month_start,
    )
    count = len(list(session.exec(query).all()))
    return {"count": count, "since": month_start.date().isoformat()}


def resolve_live_scan_activity(session: Session, ws_ids, config: dict) -> dict:
    """Every scan currently running, most-recently-started first (issue
    #224). Same query GET /api/scans/active uses (Scan.status == "running",
    workspace-scoped, stale rows swept via mark_stale_if_needed);
    duplicated here rather than imported, since that endpoint returns a
    by-target dict shaped for the target detail page's scan-buttons UI,
    not the flat most-recent-first list this widget wants.
    """
    from app.core import scan_eta
    from app.core.staleness import mark_stale_if_needed
    from app.models.models import Scan

    limit = max(1, min(int(config.get("limit", 8)), 50))
    # (#273) The twin of GET /api/scans/active's own filter, and it has to be
    # here too rather than inherited: this resolver builds its own query
    # instead of calling that endpoint (see the docstring above). Without
    # it, a deleted target's in-flight scan keeps rendering -- and because
    # _target_names() correctly refuses to resolve a deleted target, the
    # widget shows the literal fallback string "target #47" rather than a
    # name, which is the worst of both outcomes.
    query = target_lifecycle.exclude_deleted_targets(
        select(Scan).where(Scan.status == "running"), Scan.target_id
    )
    if ws_ids is not None:
        query = query.join(Target, Target.id == Scan.target_id).where(Target.workspace_id.in_(ws_ids))
    running = list(session.exec(query).all())

    items = []
    for scan in running:
        # Re-check after the sweep, same as GET /api/scans/active: a row
        # that just timed out is no longer active and must not be reported
        # as such.
        if mark_stale_if_needed(session, scan):
            continue
        items.append(scan)
    items.sort(key=lambda s: s.started_at, reverse=True)

    names = _target_names(session, {s.target_id for s in items})
    return {
        "count": len(items),
        "items": [
            {
                "scan_id": s.id,
                "tool": s.tool,
                "target_id": s.target_id,
                "target_name": names.get(s.target_id, f"target #{s.target_id}"),
                "branch": s.branch,
                "started_at": s.started_at.isoformat() + "Z",
                **scan_eta.progress_for(session, s),
            }
            for s in items[:limit]
        ],
    }


def resolve_ai_ml_risk(session: Session, ws_ids, config: dict) -> dict:
    """AI/ML-repo count plus open findings from the two AI-specific scanners
    (issue #224): AI-repo detection (#185), ModelScan (#186) and the LLM
    ruleset (#189) shipped with no dashboard-level visibility at all; an
    org with several AI/ML repos had no way to tell from the dashboard
    whether those scanners had found anything without already knowing to
    filter Findings by tool name.
    """
    from app.core.ai_repo_status import effective_is_ai_repo

    targets = _scoped_targets(session, ws_ids)
    ai_target_ids = {t.id for t in targets if effective_is_ai_repo(t)}

    findings = list(session.exec(_scoped_findings_query(ws_ids)).all())
    open_findings = [f for f in findings if f.state in OPEN_STATES]
    modelscan_open = sum(1 for f in open_findings if f.tool == "modelscan")
    semgrep_llm_open = sum(1 for f in open_findings if f.tool == "semgrep-llm")

    return {
        "ai_repo_count": len(ai_target_ids),
        "modelscan_open": modelscan_open,
        "semgrep_llm_open": semgrep_llm_open,
    }


def resolve_guardrail_activity(session: Session, ws_ids, config: dict) -> dict:
    """Recent PR Guardrail scan decisions plus the pending-approval count
    (issue #224), the Approval Queue (moved to its own nav item this same
    IA pass) is daily work with no at-a-glance visibility on the dashboard
    itself; this surfaces both "is PR Guardrail actually catching things"
    and "is anything waiting on security review" without a click.
    """
    from app.models.models import IgnoreStatus, PRGuardrailFinding, PRGuardrailScan

    limit = max(1, min(int(config.get("limit", 5)), 25))
    targets = _scoped_targets(session, ws_ids)
    target_by_id = {t.id: t for t in targets}
    if not target_by_id:
        return {"pending_approvals": 0, "items": []}

    scans = list(
        session.exec(
            select(PRGuardrailScan)
            .where(PRGuardrailScan.target_id.in_(target_by_id.keys()))
            .order_by(PRGuardrailScan.created_at.desc())
            .limit(limit)
        ).all()
    )
    pending_approvals = len(
        list(
            session.exec(
                select(PRGuardrailFinding)
                .join(PRGuardrailScan, PRGuardrailScan.id == PRGuardrailFinding.pr_scan_id)
                .where(
                    PRGuardrailScan.target_id.in_(target_by_id.keys()),
                    PRGuardrailFinding.ignore_status == IgnoreStatus.REQUESTED,
                )
            ).all()
        )
    )

    return {
        "pending_approvals": pending_approvals,
        "items": [
            {
                "pr_scan_id": s.id,
                "target_id": s.target_id,
                "target_name": target_by_id[s.target_id].name,
                "pr_number": s.pr_number,
                "pr_title": s.pr_title,
                "status": s.status,
                "new_findings_count": s.new_findings_count,
                "highest_new_severity": s.highest_new_severity,
                "created_at": s.created_at.isoformat() + "Z",
            }
            for s in scans
        ],
    }


WIDGET_CATALOG: dict[str, dict[str, Any]] = {
    "kpi_cards": {
        "name": "KPI Cards",
        "description": "Open / critical / high / mitigated vulnerability counts and targets onboarded. Licence findings are counted separately.",
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
        # Catalog id kept as `recent_findings` for backward compatibility
        # with DashboardLayout rows saved before this widget's data source
        # changed; the name/description/resolver below are what actually
        # changed. See resolve_needs_action_queue's docstring for why.
        "name": "Needs Action Queue",
        "description": "Top of the Needs Action queue: open, non-licence findings grouped the same way the Findings page groups them.",
        "resolver": resolve_needs_action_queue,
        "default_config": {"limit": 5},
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
    "live_scan_activity": {
        "name": "Live Scan Activity",
        "description": "Scans currently running, most-recently-started first.",
        "resolver": resolve_live_scan_activity,
        "default_config": {"limit": 8},
    },
    "ai_ml_risk": {
        "name": "AI/ML Risk",
        "description": "AI/ML-detected repos plus open ModelScan and LLM-ruleset findings.",
        "resolver": resolve_ai_ml_risk,
        "default_config": {},
    },
    "guardrail_activity": {
        "name": "Guardrail Activity",
        "description": "Recent PR Guardrail scan decisions plus findings pending security review.",
        "resolver": resolve_guardrail_activity,
        "default_config": {"limit": 5},
    },
}

# Sensible out-of-the-box composition for a user with no saved
# DashboardLayout row yet. Order mirrors the previous fixed dashboard
# (frontend/(dashboard)/page.tsx pre-#69) reasonably closely. security_score
# leads the list (#63); a CISO/CTO's single-number read on posture belongs
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
    uuid4); this is regenerated on every call for a user with no saved
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
