import time

import httpx

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TIMEOUT_SECONDS = 20.0

# The catalog is a few MB of JSON; re-downloading it synchronously on every
# ingestion call (security review finding: up to 20s blocking a threadpool
# worker per request, and CI push endpoints get hit far more often than the
# KEV list actually changes) was a real availability problem. A KEV catalog
# update is a rare event -- caching it in-process for an hour trades a small
# amount of staleness for removing that blocking cost from the hot path.
_CACHE_TTL_SECONDS = 60 * 60
_cache: dict[str, object] = {"cve_ids": None, "fetched_at": 0.0}


def fetch_kev_cve_set() -> set[str]:
    """
    Return the set of CVE IDs in CISA's Known Exploited Vulnerabilities (KEV)
    catalog, refetching at most once per _CACHE_TTL_SECONDS.

    Never raises: any network failure, timeout, or non-200 response results
    in an empty set (or the last good cached set, if one exists) so that KEV
    lookup failures can never break scan ingestion.
    """
    now = time.monotonic()
    if _cache["cve_ids"] is not None and now - _cache["fetched_at"] < _CACHE_TTL_SECONDS:
        return _cache["cve_ids"]

    try:
        response = httpx.get(KEV_CATALOG_URL, timeout=KEV_TIMEOUT_SECONDS)
        if response.status_code != 200:
            return _cache["cve_ids"] or set()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return _cache["cve_ids"] or set()

    cve_ids: set[str] = set()
    for vuln in payload.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if cve_id:
            cve_ids.add(cve_id)

    _cache["cve_ids"] = cve_ids
    _cache["fetched_at"] = now
    return cve_ids
