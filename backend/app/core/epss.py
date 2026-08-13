import httpx

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_TIMEOUT_SECONDS = 10.0


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Batch-fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org for the
    given CVE IDs, returning {cve_id: epss_score}.

    All CVEs are queried in a single request (comma-separated `cve` param) rather than
    one request per CVE, so ingesting a scan with many CVEs stays cheap.

    Never raises: any network failure, timeout, or non-200 response results in an empty
    dict so that EPSS lookup failures can never break scan ingestion.
    """
    unique_cve_ids = sorted(set(cve_ids))
    if not unique_cve_ids:
        return {}

    try:
        response = httpx.get(
            EPSS_API_URL,
            params={"cve": ",".join(unique_cve_ids)},
            timeout=EPSS_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            return {}
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return {}

    scores: dict[str, float] = {}
    for entry in payload.get("data", []):
        cve = entry.get("cve")
        raw_score = entry.get("epss")
        if not cve or raw_score is None:
            continue
        try:
            scores[cve] = float(raw_score)
        except (TypeError, ValueError):
            continue

    return scores
