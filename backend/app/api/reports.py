"""Compliance / audit-evidence posture reports (CSV + PDF export).

Reuses the same "default branch is the org's current state" convention as
GET /api/dashboard/posture and the persisted-state-only SBOM endpoints;
this pulls real rows out of Finding / Scan / SbomComponent, never
fabricated content, matching the pattern already established by
GET /api/sbom/{target_id}/export and GET /api/sbom/org/export.
"""
import csv
import io
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlmodel import Session, func, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.models.models import Finding, FindingState, Scan, SbomComponent, Target, User

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_targets(session: Session, target_id: Optional[int], ws_ids: Optional[list[int]]) -> list[Target]:
    """`ws_ids` is `accessible_workspace_ids()`'s result; None for admins
    (no filter), else the caller's workspace ids (issue #86, same
    unscoped-aggregate bug class #57 fixed on dashboard/findings/targets).
    A caller with no memberships (ws_ids == []) gets an empty report rather
    than every workspace's data."""
    if target_id is None:
        query = select(Target).order_by(Target.name)
        if ws_ids is not None:
            if not ws_ids:
                return []
            query = query.where(Target.workspace_id.in_(ws_ids))
        return list(session.exec(query).all())
    target = session.get(Target, target_id)
    if not target or (ws_ids is not None and target.workspace_id not in ws_ids):
        # 404 rather than 403 to avoid confirming the target exists in a
        # workspace the caller can't see (matches findings.py's get_finding).
        raise HTTPException(status_code=404, detail="target not found")
    return [target]


def _enum_value(v) -> str:
    """Normalize a Severity/FindingState enum (or plain str) query result to
    its plain string value, str(Severity.CRITICAL) renders as
    'Severity.CRITICAL' via Enum's default __str__, which is not what
    belongs in an audit report."""
    return v.value if hasattr(v, "value") else v


def _age_bucket(age_days: int) -> str:
    if age_days <= 7:
        return "0-7d"
    if age_days <= 30:
        return "8-30d"
    if age_days <= 90:
        return "31-90d"
    return "90d+"


def build_posture_report(session: Session, target_id: Optional[int], ws_ids: Optional[list[int]]) -> dict:
    """Assemble the real audit-evidence dataset: finding counts by
    severity/state, SLA/age of open findings, scan history/coverage, and an
    SBOM component summary; all scoped to each target's default branch,
    mirroring GET /api/dashboard/posture's convention. `ws_ids` scopes the
    org-wide (target_id is None) case to the caller's workspaces (issue #86)."""
    targets = _get_targets(session, target_id, ws_ids)
    now = datetime.utcnow()

    severity_state_rows: list[dict] = []
    open_age_rows: list[dict] = []
    scan_rows: list[dict] = []
    sbom_rows: list[dict] = []

    totals_by_severity_state: dict[tuple[str, str], int] = {}

    for target in targets:
        breakdown_rows = session.exec(
            select(Finding.severity, Finding.state, func.count())
            .where(Finding.target_id == target.id, Finding.branch == target.default_branch)
            .group_by(Finding.severity, Finding.state)
        ).all()
        for severity, state, count in breakdown_rows:
            severity = _enum_value(severity)
            state = _enum_value(state)
            severity_state_rows.append(
                {"target": target.name, "severity": severity, "state": state, "count": count}
            )
            key = (severity, state)
            totals_by_severity_state[key] = totals_by_severity_state.get(key, 0) + count

        open_findings = session.exec(
            select(Finding).where(
                Finding.target_id == target.id,
                Finding.branch == target.default_branch,
                Finding.state == FindingState.OPEN,
            )
        ).all()
        ages_by_severity: dict[str, list[int]] = {}
        for f in open_findings:
            age_days = max((now - f.first_seen).days, 0)
            ages_by_severity.setdefault(_enum_value(f.severity), []).append(age_days)
        for severity, ages in sorted(ages_by_severity.items()):
            buckets: dict[str, int] = {}
            for a in ages:
                b = _age_bucket(a)
                buckets[b] = buckets.get(b, 0) + 1
            open_age_rows.append(
                {
                    "target": target.name,
                    "severity": severity,
                    "open_count": len(ages),
                    "avg_age_days": round(sum(ages) / len(ages), 1) if ages else 0,
                    "oldest_age_days": max(ages) if ages else 0,
                    "bucket_0_7d": buckets.get("0-7d", 0),
                    "bucket_8_30d": buckets.get("8-30d", 0),
                    "bucket_31_90d": buckets.get("31-90d", 0),
                    "bucket_90d_plus": buckets.get("90d+", 0),
                }
            )

        # Latest scan per tool for this target; "coverage" is which
        # (target, tool) pairs have ever been scanned and when they last ran,
        # not a full run-by-run history.
        all_scans = session.exec(
            select(Scan).where(Scan.target_id == target.id).order_by(Scan.started_at.desc())
        ).all()
        seen_tools: set[str] = set()
        for s in all_scans:
            if s.tool in seen_tools:
                continue
            seen_tools.add(s.tool)
            scan_rows.append(
                {
                    "target": target.name,
                    "tool": s.tool,
                    "branch": s.branch,
                    "status": s.status,
                    "started_at": s.started_at.isoformat() + "Z",
                    "completed_at": (s.completed_at.isoformat() + "Z") if s.completed_at else "",
                    "findings_count": s.findings_count,
                }
            )
        if not all_scans:
            scan_rows.append(
                {
                    "target": target.name,
                    "tool": "",
                    "branch": target.default_branch,
                    "status": "never scanned",
                    "started_at": "",
                    "completed_at": "",
                    "findings_count": 0,
                }
            )

        components = session.exec(
            select(SbomComponent).where(
                SbomComponent.target_id == target.id, SbomComponent.branch == target.default_branch
            )
        ).all()
        last_updated = max((c.last_seen for c in components), default=None)
        sbom_rows.append(
            {
                "target": target.name,
                "component_count": len(components),
                "last_updated": (last_updated.isoformat() + "Z") if last_updated else "",
            }
        )

    totals_rows = [
        {"severity": severity, "state": state, "count": count}
        for (severity, state), count in sorted(totals_by_severity_state.items())
    ]

    return {
        "generated_at": now.isoformat() + "Z",
        "scope": "org-wide (all targets)" if target_id is None else targets[0].name,
        "target_count": len(targets),
        "targets": [
            {"id": t.id, "name": t.name, "repo_url": t.repo_url, "label": t.label, "default_branch": t.default_branch}
            for t in targets
        ],
        "totals_by_severity_state": totals_rows,
        "severity_state_rows": severity_state_rows,
        "open_age_rows": open_age_rows,
        "scan_rows": scan_rows,
        "sbom_rows": sbom_rows,
    }


def render_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["Toleman Compliance Posture Report"])
    writer.writerow(["Generated At", data["generated_at"]])
    writer.writerow(["Scope", data["scope"]])
    writer.writerow(["Target Count", data["target_count"]])
    writer.writerow([])

    writer.writerow(["Targets"])
    writer.writerow(["ID", "Name", "Repo URL", "Label", "Default Branch"])
    for t in data["targets"]:
        writer.writerow([t["id"], t["name"], t["repo_url"], t["label"], t["default_branch"]])
    writer.writerow([])

    writer.writerow(["Finding Totals By Severity And State (all in-scope targets)"])
    writer.writerow(["Severity", "State", "Count"])
    for r in data["totals_by_severity_state"]:
        writer.writerow([r["severity"], r["state"], r["count"]])
    writer.writerow([])

    writer.writerow(["Finding Counts By Target, Severity, State"])
    writer.writerow(["Target", "Severity", "State", "Count"])
    for r in data["severity_state_rows"]:
        writer.writerow([r["target"], r["severity"], r["state"], r["count"]])
    writer.writerow([])

    writer.writerow(["Open Finding Age / SLA (default branch)"])
    writer.writerow(
        [
            "Target",
            "Severity",
            "Open Count",
            "Avg Age (days)",
            "Oldest Age (days)",
            "0-7d",
            "8-30d",
            "31-90d",
            "90d+",
        ]
    )
    for r in data["open_age_rows"]:
        writer.writerow(
            [
                r["target"],
                r["severity"],
                r["open_count"],
                r["avg_age_days"],
                r["oldest_age_days"],
                r["bucket_0_7d"],
                r["bucket_8_30d"],
                r["bucket_31_90d"],
                r["bucket_90d_plus"],
            ]
        )
    writer.writerow([])

    writer.writerow(["Scan History / Coverage (latest run per tool)"])
    writer.writerow(["Target", "Tool", "Branch", "Status", "Started At", "Completed At", "Findings Count"])
    for r in data["scan_rows"]:
        writer.writerow(
            [r["target"], r["tool"], r["branch"], r["status"], r["started_at"], r["completed_at"], r["findings_count"]]
        )
    writer.writerow([])

    writer.writerow(["SBOM Component Summary (default branch)"])
    writer.writerow(["Target", "Component Count", "Last Updated"])
    for r in data["sbom_rows"]:
        writer.writerow([r["target"], r["component_count"], r["last_updated"]])

    return buf.getvalue()


def render_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="Toleman Compliance Posture Report")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Toleman Compliance Posture Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]))
    story.append(Paragraph(f"Scope: {data['scope']}", styles["Normal"]))
    story.append(Paragraph(f"Targets in scope: {data['target_count']}", styles["Normal"]))
    story.append(Spacer(1, 0.25 * inch))

    def add_table(heading: str, header: list[str], rows: list[list]):
        story.append(Paragraph(heading, styles["Heading2"]))
        if not rows:
            story.append(Paragraph("No data.", styles["Normal"]))
            story.append(Spacer(1, 0.2 * inch))
            return
        table_data = [header] + rows
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.25 * inch))

    add_table(
        "Targets in Scope",
        ["ID", "Name", "Repo URL", "Label", "Default Branch"],
        [[t["id"], t["name"], t["repo_url"], t["label"], t["default_branch"]] for t in data["targets"]],
    )

    add_table(
        "Finding Totals By Severity And State",
        ["Severity", "State", "Count"],
        [[r["severity"], r["state"], r["count"]] for r in data["totals_by_severity_state"]],
    )

    add_table(
        "Finding Counts By Target, Severity, State",
        ["Target", "Severity", "State", "Count"],
        [[r["target"], r["severity"], r["state"], r["count"]] for r in data["severity_state_rows"]],
    )

    add_table(
        "Open Finding Age / SLA (default branch)",
        ["Target", "Severity", "Open", "Avg Age (d)", "Oldest (d)", "0-7d", "8-30d", "31-90d", "90d+"],
        [
            [
                r["target"],
                r["severity"],
                r["open_count"],
                r["avg_age_days"],
                r["oldest_age_days"],
                r["bucket_0_7d"],
                r["bucket_8_30d"],
                r["bucket_31_90d"],
                r["bucket_90d_plus"],
            ]
            for r in data["open_age_rows"]
        ],
    )

    add_table(
        "Scan History / Coverage (latest run per tool)",
        ["Target", "Tool", "Branch", "Status", "Started At", "Completed At", "Findings"],
        [
            [r["target"], r["tool"], r["branch"], r["status"], r["started_at"], r["completed_at"], r["findings_count"]]
            for r in data["scan_rows"]
        ],
    )

    add_table(
        "SBOM Component Summary (default branch)",
        ["Target", "Component Count", "Last Updated"],
        [[r["target"], r["component_count"], r["last_updated"]] for r in data["sbom_rows"]],
    )

    doc.build(story)
    return buf.getvalue()


@router.get("/posture")
def posture_report(
    target_id: Optional[int] = Query(default=None),
    format: str = Query(default="csv", pattern="^(csv|pdf)$"),
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Real audit-evidence posture report (finding counts by
    severity/state, open-finding SLA/age, scan coverage, and SBOM summary)
    built from persisted Finding/Scan/SbomComponent rows. target_id omitted
    means org-wide (every target the caller can see), same "0/omitted = all"
    convention as TargetPicker's ALL_TARGETS sentinel on the frontend.

    Issue #86: the org-wide case is scoped to the caller's workspaces via
    accessible_workspace_ids(), the same helper #57 applied to
    dashboard/findings/targets but which reports.py was out of scope for at
    the time. A specific target_id outside the caller's workspaces 404s
    (see _get_targets), matching findings.py's get_finding."""
    ws_ids = accessible_workspace_ids(session, user)
    data = build_posture_report(session, target_id, ws_ids)

    scope_slug = "org-wide" if target_id is None else data["targets"][0]["name"].replace(" ", "-")
    date_slug = datetime.utcnow().strftime("%Y%m%d")

    if format == "pdf":
        pdf_bytes = render_pdf(data)
        filename = f"toleman-posture-report-{scope_slug}-{date_slug}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    csv_text = render_csv(data)
    filename = f"toleman-posture-report-{scope_slug}-{date_slug}.csv"
    return StreamingResponse(
        iter([csv_text]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
