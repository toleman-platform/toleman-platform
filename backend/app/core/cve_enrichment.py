import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from app.core.nvd import fetch_nvd_cve
from app.core.osv import fetch_osv_vuln
from app.models.models import CveEnrichment


def get_cve_enrichment(session: Session, cve_id: str) -> CveEnrichment:
    """
    Return the cached CveEnrichment row for cve_id (issue #71), fetching
    from NVD + OSV.dev and persisting on first lookup.

    NVD/OSV data for an already-published CVE is effectively immutable, so
    once a row exists here it is never re-fetched -- a real forever-cache
    (in contrast to core/epss.py and core/kev.py's short in-process TTL,
    which is right for those because they track whole catalogs that
    genuinely change; a single CVE's description/CVSS/fix version does not).

    A CVE for which both lookups fail (network down, or genuinely not
    indexed by either source) is still cached with nvd_found=osv_found=False
    -- this is what actually removes the blocking per-request network cost
    from the hot path per the issue's caching requirement, at the cost of
    not automatically retrying a transient outage. Given NVD/OSV's
    reliability in practice this is an acceptable tradeoff; a future retry
    policy for the not-found case can be added without a schema change.
    """
    existing = session.exec(select(CveEnrichment).where(CveEnrichment.cve_id == cve_id)).first()
    if existing:
        return existing

    nvd_data = fetch_nvd_cve(cve_id)
    osv_data = fetch_osv_vuln(cve_id)

    row = CveEnrichment(
        cve_id=cve_id,
        nvd_found=nvd_data is not None,
        osv_found=osv_data is not None,
        fetched_at=datetime.now(UTC).replace(tzinfo=None),
    )
    if nvd_data:
        row.nvd_description = nvd_data["description"] or None
        row.cvss_score = nvd_data["cvss_score"]
        row.cvss_vector = nvd_data["cvss_vector"]
        row.cwe_ids = json.dumps(nvd_data["cwe_ids"]) if nvd_data["cwe_ids"] else None
        row.nvd_references = json.dumps(nvd_data["references"]) if nvd_data["references"] else None
    if osv_data:
        row.osv_id = osv_data["osv_id"]
        row.fixed_versions = json.dumps(osv_data["fixed_versions"]) if osv_data["fixed_versions"] else None
        row.osv_references = json.dumps(osv_data["references"]) if osv_data["references"] else None

    session.add(row)
    session.commit()
    session.refresh(row)
    return row
