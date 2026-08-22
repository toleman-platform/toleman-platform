import csv
import io
import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlmodel import Session, select

from app.api.auth import require_workspace_role
from app.api.deps import get_session
from app.core.aibom import UNKNOWN as AIBOM_UNKNOWN
from app.core.async_jobs import create_running_row
from app.core.aibom import AiComponent, aibom_summary, build_aibom
from app.core.sbom_ingestion import upsert_components  # noqa: F401 -- re-exported, see note below
from app.core.staleness import mark_stale_if_needed
from app.models.models import AiBomComponent, SbomComponent, SbomRun, Target, User, WorkspaceRole
from app.tasks.sbom_tasks import run_sbom_generation

router = APIRouter(prefix="/api/sbom", tags=["sbom"])

# upsert_components used to be defined in this module; it now lives in
# app.core.sbom_ingestion (#59) so app.tasks.sbom_tasks -- which does the
# actual clone+scan work on a Celery worker -- can import it without an
# app.api.sbom <-> app.tasks.sbom_tasks import cycle. Re-imported above (not
# re-implemented) so `from app.api.sbom import upsert_components` (used by
# tests) keeps working unchanged.


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


def _serialize(components: list[SbomComponent], new_ids: set[int]) -> list[dict]:
    return [
        {
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "package_type": c.package_type,
            "purl": c.purl,
            # (#227) Which source reported this. "github" alone is the
            # signal that a package is transitive -- trivy reads manifests,
            # so anything only GitHub's resolved graph knows about is by
            # definition not pinned in one.
            "source": c.source,
            "is_new": c.id in new_ids,
            "first_seen": c.first_seen,
            "last_seen": c.last_seen,
        }
        for c in components
    ]


def _aggregate_org_components(session: Session) -> tuple[list[dict], dict, list[Target], dict[int, Target]]:
    """Group every persisted SbomComponent (default branch, per target) by
    (name, version, purl) across all targets -- read-only, no scans triggered.
    Mirrors the per-target GET's persisted-state-only pattern, just widened to
    every Target row (this app has no workspace-scoping on list_targets() yet,
    so 'org-wide' here means every Target in the DB, matching that)."""
    targets = session.exec(select(Target)).all()
    targets_by_id = {t.id: t for t in targets}

    # Only the target's own default branch counts as "current" SBOM state,
    # same as the per-target GET/export -- fetch per target rather than one
    # unscoped query so a stale non-default-branch row never leaks in.
    groups: dict[tuple[str, str, str], dict] = {}
    targets_with_sbom: set[int] = set()
    for target in targets:
        components = session.exec(
            select(SbomComponent).where(
                SbomComponent.target_id == target.id, SbomComponent.branch == target.default_branch
            )
        ).all()
        if components:
            targets_with_sbom.add(target.id)
        for c in components:
            key = (c.name, c.version, c.purl)
            group = groups.get(key)
            if group is None:
                group = {
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "package_type": c.package_type,
                    "target_ids": [],
                }
                groups[key] = group
            if target.id not in group["target_ids"]:
                group["target_ids"].append(target.id)

    ordered = sorted(groups.values(), key=lambda g: (g["name"], g["version"]))
    summary = {
        "targets_with_sbom_count": len(targets_with_sbom),
        "total_targets_count": len(targets),
        "unique_component_count": len(ordered),
    }
    return ordered, summary, targets, targets_by_id


# NOTE: these two literal routes ("/org", "/org/export") MUST be registered
# before the "/{target_id}" routes below. The path is declared as a bare
# "/{target_id}" (no ":int" converter in the path itself), so Starlette's
# routing matches it against ANY string first -- "org" would otherwise match
# "/{target_id}" and only fail afterwards, at FastAPI's int-parsing
# validation step, returning a 422 instead of ever reaching this handler.
@router.get("/org")
def get_org_sbom(session: Session = Depends(get_session)):
    """Aggregate ALREADY-PERSISTED SbomComponent rows across every target's
    default branch -- read-only, does not trigger any scan. Lets a security
    engineer answer 'which of my repos still use package X@version' across
    the whole account at once."""
    ordered, summary, _targets, targets_by_id = _aggregate_org_components(session)
    components = [
        {
            "name": g["name"],
            "version": g["version"],
            "purl": g["purl"],
            "package_type": g["package_type"],
            "targets": [
                {"id": tid, "name": targets_by_id[tid].name} for tid in g["target_ids"] if tid in targets_by_id
            ],
        }
        for g in ordered
    ]
    return {**summary, "components": components}


@router.get("/org/export")
def export_org_sbom(session: Session = Depends(get_session)):
    """Downloadable JSON of the org-wide aggregation -- same persisted data as
    GET /api/sbom/org, just as a file. Not CycloneDX since it spans multiple
    repos; a custom schema is reasonable here."""
    ordered, summary, targets, _targets_by_id = _aggregate_org_components(session)
    document = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "targets": [{"id": t.id, "name": t.name} for t in targets],
        "components": [
            {
                "name": g["name"],
                "version": g["version"],
                "purl": g["purl"],
                "package_type": g["package_type"],
                "target_ids": g["target_ids"],
            }
            for g in ordered
        ],
        **summary,
    }
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": 'attachment; filename="sbom-org-wide.json"'},
    )


@router.post("/{target_id}")
def generate_sbom(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Dispatch an async SBOM generation run (#59) instead of cloning+
    running trivy synchronously inside the request handler -- a handful of
    concurrent requests here used to be enough to exhaust FastAPI's
    threadpool. Creates a SbomRun row (status="running"), hands the actual
    clone+scan work to app.tasks.sbom_tasks.run_sbom_generation via
    .delay(), and returns immediately with the run's id. Poll
    GET /api/sbom/{target_id}/runs/{run_id} until status leaves "running" to
    get the same components/new_count payload this used to return
    synchronously."""
    target = _get_target(target_id, session)

    run = create_running_row(
        session, SbomRun(target_id=target_id, branch=target.default_branch, status="running")
    )

    run_sbom_generation.delay(target_id=target_id, run_id=run.id)

    return JSONResponse(
        status_code=202,
        content={"run_id": run.id, "target_id": target_id, "status": run.status},
    )


@router.get("/{target_id}/runs/{run_id}")
def get_sbom_run(target_id: int, run_id: int, session: Session = Depends(get_session)):
    """Poll target for an async SBOM generation run dispatched by POST
    above. Once status leaves "running", also returns the same
    components/new_count payload the old synchronous POST used to return
    directly."""
    run = session.get(SbomRun, run_id)
    if not run or run.target_id != target_id:
        raise HTTPException(status_code=404, detail="sbom run not found")
    mark_stale_if_needed(session, run)

    target = _get_target(target_id, session)
    payload = {
        "run_id": run.id,
        "target_id": run.target_id,
        "status": run.status,
        "count": run.count,
        "new_count": run.new_count,
        "error": run.error,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
    }
    if run.status != "running":
        new_id_set = {int(x) for x in run.new_ids.split(",") if x}
        all_components = session.exec(
            select(SbomComponent).where(
                SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch
            )
        ).all()
        payload["components"] = _serialize(all_components, new_id_set)
    return payload


@router.get("/{target_id}")
def list_sbom_components(target_id: int, session: Session = Depends(get_session)):
    """Persisted results without re-running a scan -- same GET-reads-persisted-
    state pattern as GET /api/discovery/{target_id}."""
    target = _get_target(target_id, session)
    components = session.exec(
        select(SbomComponent)
        .where(SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch)
        .order_by(SbomComponent.name)
    ).all()
    return {
        "target_id": target_id,
        "count": len(components),
        "components": _serialize(components, set()),
    }


def _build_cyclonedx_document(target: Target, components: list[SbomComponent]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {"type": "application", "name": target.name},
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "properties": [{"name": "rikugan:packageType", "value": c.package_type}],
            }
            for c in components
        ],
    }


def _spdx_package_id(component: SbomComponent) -> str:
    # SPDXID must be a valid SPDX reference identifier -- [A-Za-z0-9.-] only
    # (SPDX spec sec 11.1) -- so package name/version (which can contain
    # slashes, @, etc. for scoped npm packages) can't be used directly.
    slug = re.sub(r"[^A-Za-z0-9.-]", "-", f"{component.name}-{component.version}")
    return f"SPDXRef-Package-{slug}-{component.id}"


def _build_spdx_document(target: Target, components: list[SbomComponent]) -> dict:
    """Minimal, valid SPDX 2.3 JSON document -- the other widely-used SBOM
    standard alongside CycloneDX (issue #121's export-parity ask). Each
    persisted component becomes one `packages[]` entry plus a
    DESCRIBES relationship from the document root, same shape a real SPDX
    consumer (e.g. an org's compliance tooling) expects to parse."""
    now = datetime.utcnow().isoformat() + "Z"
    # rikugan.local, not rikugan.io -- the project doesn't own that domain;
    # SPDX only requires this namespace be a unique URI, not a resolvable
    # one, so a non-registrable domain is safe here (#154).
    doc_namespace = f"https://rikugan.local/spdx/{target.name}-{uuid.uuid4()}"
    root_id = "SPDXRef-DOCUMENT"
    packages = [
        {
            "SPDXID": _spdx_package_id(c),
            "name": c.name,
            "versionInfo": c.version,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }
            ]
            if c.purl
            else [],
        }
        for c in components
    ]
    relationships = [
        {"spdxElementId": root_id, "relationshipType": "DESCRIBES", "relatedSpdxElement": p["SPDXID"]}
        for p in packages
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": root_id,
        "name": f"{target.name}-{target.default_branch}",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": now,
            "creators": ["Tool: rikugan-sbom"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def _render_sbom_csv(target: Target, components: list[SbomComponent]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Target", target.name])
    writer.writerow(["Branch", target.default_branch])
    writer.writerow(["Generated At", datetime.utcnow().isoformat() + "Z"])
    writer.writerow([])
    writer.writerow(["Name", "Version", "Package Type", "PURL"])
    for c in components:
        writer.writerow([c.name, c.version, c.package_type, c.purl])
    return buf.getvalue()


def _render_sbom_pdf(target: Target, components: list[SbomComponent]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"Rikugan SBOM - {target.name}")
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Rikugan SBOM Summary — {target.name}", styles["Title"]),
        Paragraph(f"Branch: {target.default_branch}", styles["Normal"]),
        Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]),
        Paragraph(f"Components: {len(components)}", styles["Normal"]),
        Spacer(1, 0.25 * inch),
    ]
    header = ["Name", "Version", "Package Type", "PURL"]
    rows = [[c.name, c.version, c.package_type, c.purl] for c in components]
    if rows:
        table = Table([header] + rows, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No components recorded.", styles["Normal"]))
    doc.build(story)
    return buf.getvalue()


@router.get("/{target_id}/aibom")
def get_aibom(target_id: int, session: Session = Depends(get_session)):
    """AI Bill of Materials for a target (issue #190) -- models and datasets,
    the parts a package SBOM is blind to.

    Populated during SBOM generation (app/tasks/sbom_tasks.py), so this reads
    persisted rows rather than re-scanning, same as the SBOM view above.

    `generated` distinguishes "we looked and found no models" from "no AIBOM
    has ever been generated for this target". Collapsing those two into an
    empty list would let a repo that has never been analysed read as a repo
    with no AI dependencies, which is the failure mode this whole feature is
    supposed to prevent.
    """
    target = _get_target(target_id, session)
    rows = session.exec(
        select(AiBomComponent)
        .where(AiBomComponent.target_id == target_id, AiBomComponent.branch == target.default_branch)
        .order_by(AiBomComponent.component_type, AiBomComponent.name)
    ).all()

    has_run = session.exec(
        select(SbomRun).where(SbomRun.target_id == target_id, SbomRun.status == "completed").limit(1)
    ).first() is not None

    components = [
        AiComponent(
            name=r.name,
            component_type=r.component_type,
            version=r.version,
            source=r.source,
            evidence=[e.strip() for e in r.evidence.split(",") if e.strip()],
        )
        for r in rows
    ]

    return {
        "target_id": target_id,
        "target_name": target.name,
        "branch": target.default_branch,
        "generated": has_run,
        "summary": aibom_summary(components),
        "components": [
            {
                "id": r.id,
                "name": r.name,
                "component_type": r.component_type,
                "version": r.version,
                "source": r.source,
                "evidence": r.evidence,
                "unpinned": r.version == AIBOM_UNKNOWN,
                "first_seen": r.first_seen.isoformat() + "Z",
                "last_seen": r.last_seen.isoformat() + "Z",
            }
            for r in rows
        ],
    }


@router.get("/{target_id}/aibom/export")
def export_aibom(target_id: int, session: Session = Depends(get_session)):
    """Downloadable CycloneDX 1.6 AIBOM. Validated against the published
    schema in tests -- a malformed BOM offered as a compliance artifact is
    worse than none."""
    target = _get_target(target_id, session)
    rows = session.exec(
        select(AiBomComponent)
        .where(AiBomComponent.target_id == target_id, AiBomComponent.branch == target.default_branch)
        .order_by(AiBomComponent.component_type, AiBomComponent.name)
    ).all()

    components = [
        AiComponent(
            name=r.name,
            component_type=r.component_type,
            version=r.version,
            source=r.source,
            evidence=[e.strip() for e in r.evidence.split(",") if e.strip()],
        )
        for r in rows
    ]
    document = build_aibom(
        components,
        target_name=target.name,
        repo_url=target.repo_url,
        branch=target.default_branch,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    base = f"aibom-{target.name}-{target.default_branch}"
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": f'attachment; filename="{base}.cdx.json"'},
    )


@router.get("/{target_id}/export")
def export_sbom(
    target_id: int,
    format: str = Query(default="cyclonedx-json", pattern="^(cyclonedx-json|spdx-json|csv|pdf)$"),
    session: Session = Depends(get_session),
):
    """Downloadable SBOM built from persisted components -- the same real
    data shown on the page, not a re-fetch or re-scan. Issue #121: export-
    format parity with Reports (CSV/PDF) plus the two real SBOM standards
    (CycloneDX was already produced by `trivy fs --format cyclonedx`; SPDX
    JSON is the other one most compliance tooling expects)."""
    target = _get_target(target_id, session)
    components = session.exec(
        select(SbomComponent)
        .where(SbomComponent.target_id == target_id, SbomComponent.branch == target.default_branch)
        .order_by(SbomComponent.name)
    ).all()

    base = f"sbom-{target.name}-{target.default_branch}"

    if format == "spdx-json":
        document = _build_spdx_document(target, components)
        return JSONResponse(
            content=document,
            headers={"Content-Disposition": f'attachment; filename="{base}.spdx.json"'},
        )
    if format == "csv":
        csv_text = _render_sbom_csv(target, components)
        return StreamingResponse(
            iter([csv_text]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{base}.csv"'},
        )
    if format == "pdf":
        pdf_bytes = _render_sbom_pdf(target, components)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{base}.pdf"'},
        )

    document = _build_cyclonedx_document(target, components)
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": f'attachment; filename="{base}.json"'},
    )
