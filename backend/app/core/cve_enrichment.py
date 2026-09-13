import json
import logging

from sqlmodel import Session, select

from app.core.cvss import parse_cvss_vector
from app.core.nvd import fetch_nvd_cve
from app.core.osv import fetch_osv_vuln
from app.core.time import utcnow
from app.models.models import CveEnrichment

logger = logging.getLogger(__name__)


def apply_cvss_decomposition(row: CveEnrichment) -> bool:
    """Write the four decomposed CVSS metrics onto `row` (#201).

    Returns True when it changed something, so callers can skip a pointless
    commit. Purely local: parsing a vector string touches no network.

    Only writes when the parse actually established something. A vector we
    could not decode leaves the columns NULL, which is what "unknown" is
    spelled as here -- and, incidentally, is what stops an unparseable
    vector from re-writing the same row on every single read.
    """
    decomposition = parse_cvss_vector(row.cvss_vector)
    if decomposition.is_unknown:
        return False
    updated = {
        "cvss_version": decomposition.version,
        "cvss_attack_vector": decomposition.attack_vector,
        "cvss_attack_complexity": decomposition.attack_complexity,
        "cvss_privileges_required": decomposition.privileges_required,
        "cvss_user_interaction": decomposition.user_interaction,
    }
    if all(getattr(row, name) == value for name, value in updated.items()):
        return False
    for name, value in updated.items():
        setattr(row, name, value)
    return True


# How many *uncached* CVEs one ingestion run will look up. NVD's
# unauthenticated limit is 5 requests / 30s, so this is a real wall-clock
# cost (order of minutes at the cap), paid on a Celery scan task rather than
# a request. Capped so the first scan of a large monorepo after someone
# enables a CVE-backed signal does not turn into an hour of serialised NVD
# calls; the remainder is picked up by subsequent scans, which find the
# earlier batch already cached.
MAX_ENRICHMENT_LOOKUPS_PER_RUN = 25


def warm_cve_enrichment(session: Session, cve_ids: list[str]) -> int:
    """Populate the enrichment cache for CVEs that scoring is about to need
    (#201). Returns how many were actually fetched.

    The CVSS-exploitability and fixability signals both read `CveEnrichment`
    and never write it. Its only writer used to be `GET /api/findings/{id}/
    enrichment`, i.e. a human clicking a specific finding -- so those two
    signals could only ever fire for the subset of CVEs somebody had already
    browsed, no matter how high their weight. A configurable signal that
    silently cannot fire is worse than no signal, so ingestion warms the
    cache for the CVEs in its own batch.

    Called only when the workspace actually weights one of those signals
    above zero (see `app.core.ingestion`). On the shipped baseline both are
    0.0, so this does nothing and an ordinary scan makes exactly the network
    calls it made before #201 -- the cost arrives with the feature, not with
    the upgrade.

    Best-effort throughout: `get_cve_enrichment` already swallows upstream
    failures (caching a not-found row), and anything unexpected is logged
    and skipped. A scan must not fail because NVD is down.
    """
    if not cve_ids:
        return 0

    cached = set(
        session.exec(select(CveEnrichment.cve_id).where(CveEnrichment.cve_id.in_(cve_ids))).all()
    )
    missing = [cve_id for cve_id in cve_ids if cve_id not in cached]
    if not missing:
        return 0

    budget = missing[:MAX_ENRICHMENT_LOOKUPS_PER_RUN]
    if len(missing) > len(budget):
        logger.info(
            "CVE enrichment warm-up capped at %d of %d uncached CVEs this run; "
            "the rest are picked up by subsequent scans",
            len(budget),
            len(missing),
        )

    fetched = 0
    for cve_id in budget:
        try:
            get_cve_enrichment(session, cve_id)
            fetched += 1
        except Exception:
            # Never fatal to a scan. The signal stays unestablished for this
            # CVE, which contributes nothing rather than lowering anything.
            logger.exception("CVE enrichment warm-up failed for %s", cve_id)
    return fetched


def get_cve_enrichment(session: Session, cve_id: str) -> CveEnrichment:
    """
    Return the cached CveEnrichment row for cve_id (issue #71), fetching
    from NVD + OSV.dev and persisting on first lookup.

    NVD/OSV data for an already-published CVE is effectively immutable, so
    once a row exists here it is never re-fetched; a real forever-cache
    (in contrast to core/epss.py and core/kev.py's short in-process TTL,
    which is right for those because they track whole catalogs that
    genuinely change; a single CVE's description/CVSS/fix version does not).

    A CVE for which both lookups fail (network down, or genuinely not
    indexed by either source) is still cached with nvd_found=osv_found=False;
    this is what actually removes the blocking per-request network cost
    from the hot path per the issue's caching requirement, at the cost of
    not automatically retrying a transient outage. Given NVD/OSV's
    reliability in practice this is an acceptable tradeoff; a future retry
    policy for the not-found case can be added without a schema change.
    """
    existing = session.exec(select(CveEnrichment).where(CveEnrichment.cve_id == cve_id)).first()
    if existing:
        # (#201) Backfill the CVSS decomposition for rows cached before
        # those columns existed. This cache is never re-fetched by design,
        # so without a backfill on read every CVE already in an install's
        # database would stay permanently un-decomposed, and the whole
        # exploitability signal would only ever apply to CVEs discovered
        # after the upgrade. Local string parsing, no network, and it
        # settles after the first read per row.
        if apply_cvss_decomposition(existing):
            session.add(existing)
            session.commit()
            session.refresh(existing)
        return existing

    nvd_data = fetch_nvd_cve(cve_id)
    osv_data = fetch_osv_vuln(cve_id)

    row = CveEnrichment(
        cve_id=cve_id,
        nvd_found=nvd_data is not None,
        osv_found=osv_data is not None,
        fetched_at=utcnow(),
    )
    if nvd_data:
        row.nvd_description = nvd_data["description"] or None
        row.cvss_score = nvd_data["cvss_score"]
        row.cvss_vector = nvd_data["cvss_vector"]
        row.cwe_ids = json.dumps(nvd_data["cwe_ids"]) if nvd_data["cwe_ids"] else None
        row.nvd_references = json.dumps(nvd_data["references"]) if nvd_data["references"] else None
        # (#201) Decompose the vector at write time so the metrics are
        # queryable columns rather than something every reader re-parses.
        apply_cvss_decomposition(row)
    if osv_data:
        row.osv_id = osv_data["osv_id"]
        row.fixed_versions = json.dumps(osv_data["fixed_versions"]) if osv_data["fixed_versions"] else None
        row.osv_references = json.dumps(osv_data["references"]) if osv_data["references"] else None

    session.add(row)
    session.commit()
    session.refresh(row)
    return row
