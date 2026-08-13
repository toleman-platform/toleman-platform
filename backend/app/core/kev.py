import httpx

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TIMEOUT_SECONDS = 20.0


def fetch_kev_cve_set() -> set[str]:
    """
    Fetch CISA's Known Exploited Vulnerabilities (KEV) catalog and return the set of
    CVE IDs it contains.

    The catalog is a few MB of JSON, so for MVP correctness this fetches fresh on every
    call rather than caching (no staleness bugs). If this proves slow in practice, a
    reasonable follow-up is periodic caching, e.g. refreshing every few hours via a
    Celery beat task, instead of fetching per-ingestion.

    Never raises: any network failure, timeout, or non-200 response results in an empty
    set so that KEV lookup failures can never break scan ingestion.
    """
    try:
        response = httpx.get(KEV_CATALOG_URL, timeout=KEV_TIMEOUT_SECONDS)
        if response.status_code != 200:
            return set()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return set()

    cve_ids: set[str] = set()
    for vuln in payload.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if cve_id:
            cve_ids.add(cve_id)

    return cve_ids
