"""Can this finding actually be closed today? (#246)

Severity answers "which of these is worst". It does not answer "which of
these can I do anything about", and that is the question a developer with a
list of 40 findings is really asking. A wall of Criticals with no available
upgrade and no way to filter past them is how a findings list stops getting
opened.

We already resolve fixed versions from OSV during enrichment
(app/core/cve_enrichment.py -> CveEnrichment.fixed_versions). This promotes
that into a verdict.

Three values, and the third one is the point:

    fixable       OSV knows a version that fixes this
    no_known_fix  OSV has the advisory and lists no fix
    unknown       we have not established either way

`unknown` is not a polite way of saying "no fix". Enrichment is best-effort
and network-dependent -- osv_found is False when the lookup failed, when the
finding carries no CVE (most SAST and secrets findings), or when enrichment
simply has not run yet. Collapsing that into no_known_fix would tell someone
"nothing you can do" about a finding we never looked up, which is the same
class of false statement as reporting an unrun scan as clean.
"""

import json

from sqlmodel import Session, select

from app.models.models import CveEnrichment, Finding

FIXABLE = "fixable"
NO_KNOWN_FIX = "no_known_fix"
UNKNOWN = "unknown"

VALID_FIXABILITY = frozenset({FIXABLE, NO_KNOWN_FIX, UNKNOWN})


def fixability_for_enrichment(row: CveEnrichment | None) -> str:
    """Verdict from an already-loaded enrichment row."""
    if row is None or not row.osv_found:
        # No advisory resolved -- we do not know, and must not imply we do.
        return UNKNOWN
    if not row.fixed_versions:
        return NO_KNOWN_FIX
    try:
        versions = json.loads(row.fixed_versions)
    except (TypeError, ValueError):
        return UNKNOWN
    return FIXABLE if versions else NO_KNOWN_FIX


def fixability_for_finding(session: Session, finding: Finding) -> str:
    """Verdict for one finding.

    A finding with no CVE is UNKNOWN rather than NO_KNOWN_FIX: most SAST and
    secrets findings have no advisory to look up, and "no known fix" would be
    actively wrong for a hardcoded secret, whose fix is obvious.
    """
    if not finding.cve_id:
        return UNKNOWN
    row = session.exec(select(CveEnrichment).where(CveEnrichment.cve_id == finding.cve_id)).first()
    return fixability_for_enrichment(row)


def fixed_version_summary(row: CveEnrichment | None) -> str | None:
    """Shortest honest answer to "upgrade to what?" -- e.g. "0.40.0", or
    "0.40.0 (starlette)" when the advisory names a package. None when there
    is nothing to suggest.

    Picks the *lowest* fixed version offered, which is the smallest upgrade
    that clears the advisory; #247 will do the real cross-finding grouping.
    """
    if row is None or not row.fixed_versions:
        return None
    try:
        versions = json.loads(row.fixed_versions)
    except (TypeError, ValueError):
        return None
    if not versions:
        return None

    def sort_key(entry: dict):
        raw = str(entry.get("fixed") or "")
        # Numeric-aware where possible so 0.9.0 sorts below 0.10.0; falls
        # back to string order for anything non-numeric (dates, commit-ish).
        parts = []
        for chunk in raw.split("."):
            parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
        return parts

    try:
        best = sorted(versions, key=sort_key)[0]
    except Exception:
        best = versions[0]
    fixed = best.get("fixed")
    if not fixed:
        return None
    package = best.get("package")
    return f"{fixed} ({package})" if package else str(fixed)
