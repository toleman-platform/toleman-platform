"""Shared SSRF boundary for any Target-owner-configured URL that this
backend itself will later fetch (api_base_url today; anything with the same
shape tomorrow).

``update_target`` already gates ``api_base_url`` behind the global admin
role, deliberately: "These destinations can reach internal services from
the backend/worker. Only the deployment administrator can authorize that
network access." That comment means an admin pointing active scanning at
an on-prem/internal API is an intended capability, not a bug -- so this
module does **not** block RFC 1918 ranges, which would silently break that
feature for every self-hosted deployment that uses it.

What it does block is the one class of host that is never a legitimate
scan target under any deployment shape: loopback, link-local (including
169.254.169.254 and ``metadata.google.internal``, which resolves into the
same /16 -- the cloud-metadata endpoint on whatever host the backend/
worker happens to run on), and the unspecified addresses. Fetching that
endpoint on request turns "trusted admin configured a scan target" into
"the scan worker's cloud credentials get read back to whoever can trigger
a scan" -- a privilege jump from app-admin to cloud-account compromise,
which the admin gate was never meant to authorize, and which an attacker
reaches for free the moment any admin session is compromised (XSS, CSRF,
token theft) rather than needing the admin to misconfigure anything.

Deliberately IP-literal only, not hostname-resolving -- same call
github_app.py's sibling check already made, for a reason that applies
here too: resolving means doing a live DNS lookup during request
validation, which makes this check's result depend on network
reachability the caller/test/CI runner may not have (a sandboxed test
environment with no DNS egress turned every fixture using a plain
hostname into a hard failure here, which is a worse bug than the one
this module fixes). A first pass at this module did resolve hostnames;
it's deliberately walked back.

The real-world attack this still closes is the one that actually gets
used: an admin (or a compromised admin session) typing the metadata IP
directly into api_base_url, e.g. ``http://169.254.169.254/latest/
meta-data/iam/security-credentials/``. The gap this leaves is a hostname
an attacker controls the DNS for, pointed at a blocked address --
unreachable by a non-admin at all (the field is admin-gated) and not
worth trading test/CI determinism for; revisit with a resolution step
that tolerates "can't resolve right now" as inconclusive rather than
unsafe if that gap ever needs closing too.
"""
import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeScanHostError(ValueError):
    """`api_base_url` (or anything validated the same way) resolves to a
    host this backend must never fetch server-side."""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback / link-local (cloud metadata lives here) / unspecified only.

    Deliberately not `not ip.is_global`: that also catches RFC 1918, which
    is the intended destination for admin-authorized on-prem scanning (see
    module docstring). Narrower than github_app.py's sibling check on
    purpose -- that one has no legitimate internal target at all, this one
    does.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified


def _ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass
    try:
        # inet_aton accepts shorthand forms (127.1, 2130706433) that
        # ipaddress itself rejects but that resolvers/curl/browsers treat
        # as addresses; anything inet_aton also rejects is a real hostname.
        return ipaddress.ip_address(socket.inet_aton(hostname))
    except (OSError, ValueError):
        return None


def assert_safe_scan_host(url: str) -> None:
    """Raises UnsafeScanHostError if ``url``'s host is not safe for this
    backend to fetch on a caller's (indirect) request.

    Call this at every point that turns a Target's stored api_base_url
    into an actual outbound request: validating the field on write, and
    again right before the request fires. Both: the field can predate this
    check (an older row, or a row written by a path that forgot it), and a
    name's resolution can change between the two.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise UnsafeScanHostError(f"no host in URL: {url!r}")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise UnsafeScanHostError(f"{hostname!r} is a loopback host, refusing to scan it")

    literal = _ip_literal(hostname)
    if literal is not None and _is_blocked_ip(literal):
        raise UnsafeScanHostError(f"{hostname!r} is a loopback/link-local address, refusing to scan it")
