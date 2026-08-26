import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT_SECONDS = 15.0


def fetch_nvd_cve(cve_id: str) -> dict | None:
    """
    Fetch a single CVE's details from the NVD REST API v2.0 (issue #71),
    no API key required for low-volume use. This is only ever called once
    per CVE (see core/cve_enrichment.py's DB-backed forever-cache), so the
    unauthenticated public rate limit (5 requests / 30s) is respected by
    construction rather than needing its own throttling here.

    Returns None on any failure (network error, timeout, non-200, CVE not
    found) or a dict: {description, cvss_score, cvss_vector, cwe_ids,
    references}. Never raises; enrichment lookups must never break the
    findings API (same convention as core/epss.py and core/kev.py).
    """
    try:
        response = httpx.get(NVD_API_URL, params={"cveId": cve_id}, timeout=NVD_TIMEOUT_SECONDS)
        if response.status_code != 200:
            return None
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return None

    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cvss_score = None
    cvss_vector = None
    metrics = cve.get("metrics", {})
    # Prefer the newest CVSS version present: v3.1 > v3.0 > v2.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            break

    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            value = d.get("value", "")
            # NVD emits placeholder values like "NVD-CWE-noinfo"/"NVD-CWE-Other"
            # for unmapped weaknesses; only real CWE-#### entries are useful.
            if value.startswith("CWE-"):
                cwe_ids.append(value)
    cwe_ids = sorted(set(cwe_ids))

    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_ids": cwe_ids,
        "references": references[:10],
    }
