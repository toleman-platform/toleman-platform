"""Issue #72 (Active API Scanning): builds the exact, validated list of live
URLs to hand to nuclei from a Target's persisted ApiEndpoint rows plus its
operator-configured api_base_url.

This is the safety boundary for the whole feature: an active scan must only
ever hit endpoints this platform already discovered and persisted for a
target the caller already owns/has access to (via Sprint 1's static
discovery), combined with a host the target's owner explicitly declared
belongs to it (Target.api_base_url) -- never an arbitrary caller-supplied
URL. Keeping this logic in one place (rather than inline in the API route or
the Celery task) means both the dispatch-time validation and the actual scan
invocation agree on exactly the same rules.
"""
from urllib.parse import urljoin, urlparse

from sqlmodel import Session, select

from app.models.models import ApiEndpoint, Target


class ApiScanConfigError(Exception):
    """Raised when a target isn't set up for active scanning yet (no
    api_base_url) or the caller asked to scan endpoint ids that don't
    belong to this target -- both are caller/config errors, not something a
    retry fixes."""


def _join_route(base_url: str, route: str) -> str:
    """Join base_url + route, then confirm the result still resolves to
    base_url's own host.

    urljoin already treats a route starting with "/" as relative to the
    host, but a route that starts with "//" (protocol-relative) or contains
    "://" would otherwise let urljoin resolve to a *different* host entirely
    -- routes come from static regex extraction over the target's own
    source (app/scanners/discovery.py), so this should never legitimately
    happen, but a scan must never silently pivot to a third-party host, so
    it's rejected outright rather than trusted.
    """
    if "://" in route or route.startswith("//"):
        raise ApiScanConfigError(f"discovered route is not a valid path, refusing to scan: {route!r}")
    joined = urljoin(base_url if base_url.endswith("/") else base_url + "/", route.lstrip("/"))
    base_host = urlparse(base_url).netloc
    joined_host = urlparse(joined).netloc
    if joined_host != base_host:
        raise ApiScanConfigError(
            f"route {route!r} resolved outside target's configured host ({joined_host!r} != {base_host!r})"
        )
    return joined


def build_scan_urls(
    session: Session, target: Target, endpoint_ids: list[int] | None = None
) -> tuple[list[str], list[ApiEndpoint]]:
    """Returns (urls, endpoints) for the endpoints an active scan should hit.

    endpoint_ids, when given, narrows the scan to a specific selection
    (e.g. a user picking a handful of endpoints in the UI rather than
    scanning the whole target) -- every id must belong to this exact
    target+branch or it's silently dropped, never used to reach into
    another target's discovered routes.
    """
    if not target.api_base_url:
        raise ApiScanConfigError(
            "target has no api_base_url configured -- set it before running an active API scan"
        )
    parsed_base = urlparse(target.api_base_url)
    if parsed_base.scheme not in ("http", "https") or not parsed_base.netloc:
        raise ApiScanConfigError(f"target.api_base_url must be a real http(s) URL, got: {target.api_base_url!r}")

    query = select(ApiEndpoint).where(
        ApiEndpoint.target_id == target.id, ApiEndpoint.branch == target.default_branch
    )
    endpoints = session.exec(query).all()
    if endpoint_ids is not None:
        wanted = set(endpoint_ids)
        endpoints = [e for e in endpoints if e.id in wanted]

    urls: list[str] = []
    scanned_endpoints: list[ApiEndpoint] = []
    for endpoint in endpoints:
        try:
            urls.append(_join_route(target.api_base_url, endpoint.route))
            scanned_endpoints.append(endpoint)
        except ApiScanConfigError:
            # One malformed discovered route shouldn't sink the whole scan --
            # skip it, the rest of the target's endpoints still get scanned.
            continue
    return urls, scanned_endpoints
