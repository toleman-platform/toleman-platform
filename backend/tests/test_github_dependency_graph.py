"""GitHub Dependency Graph as a second SBOM source (#227, raised by
@r0075h3ll).

The gap this closes is the one #239 found from the other direction. `trivy
fs` reads dependency *manifests* and reports what is pinned there; GitHub's
Dependency Graph reports what those manifests actually *resolve to*,
including transitives that appear in no manifest at all.

#239 closed that for our own CI by resolving requirements.txt into a venv.
That deliberately does not generalise to customer repos; resolving
someone else's manifest runs arbitrary setup.py code. GitHub has already
done the resolution server-side, which is what makes this the right
mechanism here rather than a second copy of #239's approach.

The fixture is a trimmed slice of a REAL response (pallets/flask, 121
packages), not a hand-written approximation; including a self-referential
repo entry and a package with no resolved version, both of which the parser
has to handle and neither of which I would have invented.
"""

import json
from pathlib import Path

import httpx
import pytest

from app.core.github_dependency_graph import (
    DependencyGraphUnavailable,
    fetch_dependency_graph,
    parse_spdx_packages,
)
from app.core.sbom_ingestion import _merge_sources

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "github-dependency-graph-sbom.json").read_text())


class TestParsing:
    def test_parses_real_github_output(self):
        components = parse_spdx_packages(FIXTURE)
        assert components, "the recorded payload has packages; parsing must find them"
        names = {c["name"] for c in components}
        assert "uvicorn" in names
        assert "certifi" in names

    def test_excludes_the_repository_own_entry(self):
        """GitHub emits the repo itself as com.github.owner/repo. Counting it
        would inflate every inventory by one and put a 'package' in the list
        that nobody can upgrade."""
        components = parse_spdx_packages(FIXTURE)
        assert not any(c["name"].startswith("com.github.") for c in components)

    def test_ecosystem_comes_from_the_purl_not_the_name(self):
        """Verified against the real payload: GitHub emits bare names
        ('uvicorn') and puts the ecosystem only in the purl
        ('pkg:pypi/uvicorn@0.52.0'). An earlier version split an assumed
        'pypi:uvicorn' prefix off the name and produced an empty
        package_type for every single component."""
        components = parse_spdx_packages(FIXTURE)
        uvicorn = next(c for c in components if c["name"] == "uvicorn")
        assert uvicorn["package_type"] == "pypi"
        assert uvicorn["purl"] == "pkg:pypi/uvicorn@0.52.0"

    def test_handles_multiple_ecosystems_in_one_response(self):
        components = parse_spdx_packages(FIXTURE)
        types = {c["package_type"] for c in components}
        assert "pypi" in types
        assert "githubactions" in types

    def test_a_package_with_no_resolved_version_is_kept_not_dropped(self):
        """"We know this dependency is here but not which version" is
        information. Silently omitting it would under-report the inventory."""
        components = parse_spdx_packages(FIXTURE)
        assert any(c["version"] == "" for c in components)

    def test_empty_and_malformed_payloads_do_not_raise(self):
        assert parse_spdx_packages({}) == []
        assert parse_spdx_packages({"sbom": {}}) == []
        assert parse_spdx_packages({"sbom": {"packages": []}}) == []
        assert parse_spdx_packages(None) == []

    def test_a_nameless_package_is_skipped(self):
        assert parse_spdx_packages({"sbom": {"packages": [{"versionInfo": "1.0"}]}}) == []


class TestUnavailableIsNotEmpty:
    """The load-bearing distinction. A repo whose graph is disabled (the
    default for private repos) is not a repo with no dependencies.
    Returning [] for both would let a permissions problem render as a clean,
    empty inventory: the false-all-clear shape #229 and #253 are about."""

    def _stub(self, monkeypatch, status_code):
        def fake_get(*args, **kwargs):
            return httpx.Response(status_code, json={}, request=httpx.Request("GET", "https://api.github.com"))

        monkeypatch.setattr(httpx, "get", fake_get)

    def test_403_raises_rather_than_returning_empty(self, monkeypatch):
        self._stub(monkeypatch, 403)
        with pytest.raises(DependencyGraphUnavailable) as ei:
            fetch_dependency_graph("https://github.com/a/b")
        assert "disabled" in str(ei.value) or "access" in str(ei.value)

    def test_404_raises_rather_than_returning_empty(self, monkeypatch):
        self._stub(monkeypatch, 404)
        with pytest.raises(DependencyGraphUnavailable):
            fetch_dependency_graph("https://github.com/a/b")

    def test_500_raises(self, monkeypatch):
        self._stub(monkeypatch, 500)
        with pytest.raises(DependencyGraphUnavailable):
            fetch_dependency_graph("https://github.com/a/b")

    def test_network_failure_raises(self, monkeypatch):
        def boom(*args, **kwargs):
            raise httpx.ConnectError("no route to host")

        monkeypatch.setattr(httpx, "get", boom)
        with pytest.raises(DependencyGraphUnavailable) as ei:
            fetch_dependency_graph("https://github.com/a/b")
        assert "could not reach" in str(ei.value).lower()

    def test_unavailable_is_not_confused_with_a_genuinely_empty_graph(self, monkeypatch):
        """A 200 with no packages IS a real answer (GitHub looked and found
        nothing) so it returns [], not an exception. Only the cases where
        we could not ask raise."""
        def fake_get(*args, **kwargs):
            return httpx.Response(
                200, json={"sbom": {"packages": []}}, request=httpx.Request("GET", "https://api.github.com")
            )

        monkeypatch.setattr(httpx, "get", fake_get)
        assert fetch_dependency_graph("https://github.com/a/b") == []


class TestSourceMerging:
    def test_both_sources_are_recorded_not_overwritten(self):
        """A component both sources report must end up with both, not
        whichever ran second; the whole point of the second source is
        knowing which found what."""
        assert _merge_sources("trivy", "github") == "trivy,github"

    def test_order_is_stable_regardless_of_which_ran_first(self):
        """'a,b' and 'b,a' describing the same thing would defeat any query
        or UI grouping on the column."""
        assert _merge_sources("trivy", "github") == _merge_sources("github", "trivy")

    def test_repeat_of_the_same_source_does_not_duplicate(self):
        assert _merge_sources("trivy", "trivy") == "trivy"

    def test_an_unknown_source_is_preserved_not_dropped(self):
        """A source added later without updating _SOURCE_ORDER should
        degrade to unordered, not to silently discarded provenance."""
        assert "snyk" in _merge_sources("trivy,snyk", "github")
