"""Issue #72 (Active API Scanning): builds the exact, validated list of live
URLs to hand to nuclei from a Target's persisted ApiEndpoint rows plus its
operator-configured api_base_url.

This is the safety boundary for the whole feature: an active scan must only
ever hit endpoints this platform already discovered and persisted for a
target the caller already owns/has access to (via Sprint 1's static
discovery), combined with a host the target's owner explicitly declared
belongs to it (Target.api_base_url), never an arbitrary caller-supplied
URL. Keeping this logic in one place (rather than inline in the API route or
the Celery task) means both the dispatch-time validation and the actual scan
invocation agree on exactly the same rules.
"""
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from sqlmodel import Session, select

from app.core.crypto import SecretDecryptionError, decrypt_secret
from app.models.models import ApiEndpoint, Target


# Methods whose whole purpose is to destroy something. An endpoint
# discovered under one of these is not scanned by default, because a
# scanner reaching it is indistinguishable from an attacker reaching it
# and the damage is not undoable.
#
# Only DELETE is here, deliberately. PUT and PATCH modify rather than
# destroy, and POST is how most APIs express reads-with-a-body, logins and
# searches, so defaulting those off would turn active scanning off for
# most real targets while teaching operators that the setting is noise.
# For anything in those verbs that IS destructive, the answer is the
# per-endpoint exclusion below -- a decision a human made about a specific
# route, which is worth more than a guess made from its verb.
DESTRUCTIVE_METHODS = frozenset({"DELETE"})


@dataclass
class SkippedEndpoint:
    """An endpoint that was discovered but deliberately not scanned."""

    endpoint: ApiEndpoint
    reason: str


@dataclass
class ScanScope:
    """What an active scan will and will not touch.

    `skipped` is carried rather than discarded so the refusal is visible:
    a scan that quietly shrank from 40 endpoints to 6 looks identical to a
    scan of a small target, and an operator who cannot see why has no way
    to tell a working scope rule from a broken discovery run.
    """

    urls: list[str] = field(default_factory=list)
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    skipped: list[SkippedEndpoint] = field(default_factory=list)


def _methods_of(endpoint: ApiEndpoint) -> set[str]:
    """Normalised HTTP verbs for one discovered endpoint.

    discovery.py stores a single verb for fastapi/express/gin, a
    comma-joined list for flask (`methods=["GET", "POST"]`), and "-" for
    the frameworks whose routing tables it matches without recovering a
    verb at all. Splitting is therefore not optional: a flask route
    declared `methods=["GET", "DELETE"]` arrives as one string and would
    otherwise never compare equal to "DELETE".
    """
    return {part.strip().upper() for part in endpoint.method.split(",") if part.strip()}


class ApiScanConfigError(Exception):
    """Raised when a target isn't set up for active scanning yet (no
    api_base_url) or the caller asked to scan endpoint ids that don't
    belong to this target; both are caller/config errors, not something a
    retry fixes."""


def _join_route(base_url: str, route: str) -> str:
    """Join base_url + route, then confirm the result still resolves to
    base_url's own host.

    urljoin already treats a route starting with "/" as relative to the
    host, but a route that starts with "//" (protocol-relative) or contains
    "://" would otherwise let urljoin resolve to a *different* host entirely;
    routes come from static regex extraction over the target's own
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
) -> ScanScope:
    """Returns the ScanScope an active scan should hit.

    endpoint_ids, when given, narrows the scan to a specific selection
    (e.g. a user picking a handful of endpoints in the UI rather than
    scanning the whole target); every id must belong to this exact
    target+branch or it's silently dropped, never used to reach into
    another target's discovered routes.

    Two scope rules apply on top of that selection (#469):

      - An endpoint marked `excluded` is never scanned. This wins over
        everything, including an explicit endpoint_ids selection naming
        it: the exclusion is a standing operator decision that this route
        must not be touched, and a UI that lets someone re-select it by
        accident must not be able to override that.
      - An endpoint discovered under a destructive verb is skipped unless
        it was named explicitly in endpoint_ids. Naming one endpoint by id
        is already the deliberate act; a whole-target scan, or a scheduled
        one that passes no selection at all, is not, and that is exactly
        the path that would otherwise fire a DELETE nobody asked for.

    Both refusals are recorded in `skipped` rather than silently dropped.
    """
    if not target.api_base_url:
        raise ApiScanConfigError(
            "target has no api_base_url configured; set it before running an active API scan"
        )
    parsed_base = urlparse(target.api_base_url)
    if parsed_base.scheme not in ("http", "https") or not parsed_base.netloc:
        raise ApiScanConfigError(f"target.api_base_url must be a real http(s) URL, got: {target.api_base_url!r}")

    query = select(ApiEndpoint).where(
        ApiEndpoint.target_id == target.id, ApiEndpoint.branch == target.default_branch
    )
    endpoints = session.exec(query).all()
    explicitly_selected = set(endpoint_ids) if endpoint_ids is not None else None
    if explicitly_selected is not None:
        endpoints = [e for e in endpoints if e.id in explicitly_selected]

    scope = ScanScope()
    for endpoint in endpoints:
        if endpoint.excluded:
            reason = endpoint.exclusion_reason or "no reason recorded"
            scope.skipped.append(SkippedEndpoint(endpoint, f"marked out of scope ({reason})"))
            continue

        destructive = _methods_of(endpoint) & DESTRUCTIVE_METHODS
        if destructive and explicitly_selected is None:
            verbs = ", ".join(sorted(destructive))
            scope.skipped.append(
                SkippedEndpoint(
                    endpoint,
                    f"{verbs} is not scanned unless the endpoint is selected explicitly",
                )
            )
            continue

        try:
            url = _join_route(target.api_base_url, endpoint.route)
        except ApiScanConfigError as exc:
            # One malformed discovered route shouldn't sink the whole scan,
            # skip it, the rest of the target's endpoints still get scanned.
            scope.skipped.append(SkippedEndpoint(endpoint, str(exc)))
            continue
        scope.urls.append(url)
        scope.endpoints.append(endpoint)

    return scope


def build_scan_headers(target: Target) -> dict[str, str]:
    """Headers the active scanner should present for this target (#470).

    Empty dict when no credential is configured, which is the pre-existing
    anonymous behaviour and stays a supported way to run.

    A credential that cannot be decrypted raises rather than silently
    scanning anonymously. Falling back would produce a scan that answers
    401 on every authenticated route and still reports success -- an
    all-clear caused by a broken PLATFORM_ENCRYPTION_KEY, indistinguishable
    from a clean API. Failing loudly is the only honest option.
    """
    if not target.api_auth_header_name or not target.api_auth_header_value_ciphertext:
        return {}
    try:
        value = decrypt_secret(target.api_auth_header_value_ciphertext)
    except SecretDecryptionError as exc:
        raise ApiScanConfigError(
            "this target's API scan credential cannot be decrypted "
            "(PLATFORM_ENCRYPTION_KEY changed?); re-enter it before scanning"
        ) from exc
    return {target.api_auth_header_name: value}
