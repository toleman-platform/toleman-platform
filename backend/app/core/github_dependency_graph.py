"""GitHub Dependency Graph as a second SBOM source (#227, raised by
@r0075h3ll).

The gap this closes is the same one #239 found from the other direction.
`trivy fs` reads dependency *manifests* (requirements.txt, package.json)
and reports what is pinned there. GitHub's Dependency Graph reports what
those manifests actually *resolve to*, including transitive dependencies
that appear in no manifest at all. On this repo's own backend that was the
difference between 22 direct pins and ~98 installed packages, which is how
starlette@0.38.6 (7 CVEs, including an SSRF) sat unnoticed on main.

#239 closed that for our own CI by resolving requirements.txt into a real
venv and scanning site-packages. That approach deliberately does NOT
generalise to customer repositories: resolving someone else's manifest means
running `pip install` against untrusted input, which executes arbitrary
setup.py/build-hook code. runner.py's own module docstring already flags the
container isolation that would need, and does not have.

GitHub's Dependency Graph sidesteps that entirely. GitHub has already done
the resolution, server-side, and hands back the result as SPDX over the
REST API; no checkout, no install, no code execution on our side. That is
what makes this the right mechanism for target repos specifically, rather
than a second copy of what #239 built.

Availability, and why every failure here is reported rather than swallowed:

  - Public repositories have the Dependency Graph on by default.
  - Private repositories require it to be enabled explicitly by the repo
    owner (Settings > Security > Dependency graph).
  - The API 403s or 404s when it is off, and returns an empty package list
    for an ecosystem it cannot parse.

An empty or failed response therefore does NOT mean "this repo has no
dependencies". Treating it as such would be exactly the false-all-clear
shape this codebase keeps refusing (#229, #253). Every function here
distinguishes "GitHub said there is nothing" from "we could not ask", and
the caller records which; see SbomRun.sources_failed.
"""

import logging

import httpx

from app.core.github import repo_slug_from_url

logger = logging.getLogger(__name__)


class DependencyGraphUnavailable(Exception):
    """GitHub could not tell us the dependency graph for this repo.

    Deliberately NOT an empty component list. "The graph is off for this
    private repo", "the token lacks scope" and "this repo genuinely has no
    dependencies" are three different facts, and only the last one is
    evidence of anything. Collapsing them would let a permissions problem
    render as a clean, empty inventory.
    """


# SPDX package entries GitHub emits for the repository itself rather than
# for a dependency of it. Including them would inflate every count by one
# and put a "package" in the inventory that nobody can upgrade.
_SELF_REFERENTIAL_PREFIXES = ("com.github.",)


def fetch_dependency_graph(repo_url: str, token: str | None = None) -> list[dict]:
    """Resolved dependencies for a repo, via GitHub's SBOM endpoint.

    Returns the same shape upsert_components consumes (name/version/
    package_type/purl), so GitHub-sourced components merge with trivy's
    through the existing path rather than needing a parallel one.

    Raises DependencyGraphUnavailable when GitHub cannot answer; never
    returns [] to mean that.

    `token` should be resolved by the caller via
    `app.core.github_token.resolve_github_token` (issue #227); this
    function no longer falls back to the env/`gh` `GITHUB_TOKEN` pickup
    itself, since that fallback was removed entirely in favour of a single
    resolution point every target-repo call site goes through.
    """
    slug = repo_slug_from_url(repo_url)
    auth = token
    headers = {"Accept": "application/vnd.github+json"}
    if auth:
        headers["Authorization"] = f"Bearer {auth}"

    try:
        response = httpx.get(
            f"https://api.github.com/repos/{slug}/dependency-graph/sbom",
            headers=headers,
            timeout=30,
        )
    except httpx.HTTPError as exc:
        raise DependencyGraphUnavailable(f"could not reach GitHub: {exc}") from exc

    if response.status_code == 403:
        raise DependencyGraphUnavailable(
            "GitHub returned 403; the dependency graph may be disabled for this "
            "repository, or the configured token lacks access to it"
        )
    if response.status_code == 404:
        raise DependencyGraphUnavailable(
            "GitHub returned 404; the repository is not visible to the configured "
            "token, or its dependency graph has never been built"
        )
    if response.status_code != 200:
        raise DependencyGraphUnavailable(f"GitHub returned {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise DependencyGraphUnavailable(f"GitHub returned unreadable JSON: {exc}") from exc

    return parse_spdx_packages(payload)


def parse_spdx_packages(payload: dict) -> list[dict]:
    """GitHub's SPDX document -> the component shape upsert_components takes.

    Kept separate from the fetch so the parsing is testable against a
    recorded payload without a network call, and so a shape change in
    GitHub's response fails in one obvious place.
    """
    sbom = (payload or {}).get("sbom") or {}
    packages = sbom.get("packages") or []

    out: list[dict] = []
    for package in packages:
        name = (package.get("name") or "").strip()
        if not name:
            continue
        # GitHub prefixes the repo's own entry as com.github.owner/repo.
        if name.startswith(_SELF_REFERENTIAL_PREFIXES):
            continue

        purl = ""
        for ref in package.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator") or ""
                break

        # Ecosystem comes from the purl, not the name. Verified against a
        # real payload (pallets/flask, 121 packages): GitHub emits bare
        # names ("uvicorn", "certifi") and puts the ecosystem only in
        # the purl ("pkg:pypi/uvicorn@0.52.0"). An earlier version of this
        # split an assumed "pypi:uvicorn" prefix off the name and silently
        # produced an empty package_type for every component.
        #
        # Some names DO arrive qualified for ecosystems GitHub reports
        # differently (Maven's "group:artifact"), which is exactly why this
        # reads the purl rather than guessing from the name's punctuation;
        # splitting on ":" would mangle a Maven coordinate into a wrong
        # package name.
        package_type = ""
        if purl.startswith("pkg:"):
            package_type = purl[len("pkg:"):].split("/", 1)[0]

        version = package.get("versionInfo") or ""
        # A package with no resolved version is a declaration GitHub could
        # not pin. Recorded rather than dropped; "we know this is here but
        # not which version" is information; silently omitting it is not.
        out.append({
            "name": name,
            "version": version,
            "package_type": package_type,
            "purl": purl,
        })
    return out
