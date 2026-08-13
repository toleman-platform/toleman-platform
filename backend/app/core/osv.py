import httpx

OSV_API_URL = "https://api.osv.dev/v1/vulns"
OSV_TIMEOUT_SECONDS = 15.0


def fetch_osv_vuln(cve_id: str) -> dict | None:
    """
    Fetch known-fixed-version data for a CVE from OSV.dev (issue #71, free,
    no API key required). OSV's `GET /v1/vulns/{id}` endpoint resolves a CVE
    ID directly as an alias of its own OSV record, so this works from just
    the CVE ID already stored on a Trivy-sourced Finding -- no need to parse
    a package name/version out of the finding first.

    Returns None on any failure (network error, timeout, non-200, CVE not
    found in OSV -- e.g. some NVD-only CVEs have no OSV record) or a dict:
    {osv_id, fixed_versions, references}. Never raises -- enrichment lookups
    must never break the findings API (same convention as core/epss.py and
    core/kev.py).
    """
    try:
        response = httpx.get(f"{OSV_API_URL}/{cve_id}", timeout=OSV_TIMEOUT_SECONDS)
        if response.status_code != 200:
            return None
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return None

    osv_id = payload.get("id")
    if not osv_id:
        return None

    fixed_versions = []
    for affected in payload.get("affected", []):
        package = affected.get("package") or {}
        for r in affected.get("ranges", []):
            # Some OSV records (CVEs auto-converted from NVD's CPE data
            # rather than a native GHSA/PYSEC/... advisory) express GIT-type
            # ranges whose raw "fixed" event is a commit hash, not a human-
            # readable version -- ecosystems.md documents `database_specific
            # .extracted_events` as the human-readable version OSV itself
            # derived from that commit for exactly this case. Prefer it when
            # present; fall back to the raw events otherwise.
            events = (r.get("database_specific") or {}).get("extracted_events") or r.get("events", [])
            for event in events:
                fixed = event.get("fixed")
                if fixed:
                    fixed_versions.append({
                        "package": package.get("name"),
                        "ecosystem": package.get("ecosystem"),
                        "fixed": fixed,
                    })

    references = [r.get("url") for r in payload.get("references", []) if r.get("url")]

    return {
        "osv_id": osv_id,
        "fixed_versions": fixed_versions,
        "references": references[:10],
    }
