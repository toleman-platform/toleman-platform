"""Dependency findings must say whether the package ships (#500).

#488 made trivy scan npm devDependencies, taking this repo from 0 npm
findings to 8 -- one critical, two high, every one of them a dev
dependency. They then sat beside runtime-dependency CVEs with nothing
distinguishing them, so a critical in a test runner ranked identically to a
critical in a shipped library. Both are worth reporting; ranking them the
same makes the queue stop being a ranking.

The awkward part, and the reason this needed measuring rather than
guessing: trivy puts the dev flag on *Package* entries and not on
*Vulnerability* entries. A vulnerability's scope has to be resolved by
correlating its PkgID against the package list, and that list only appears
when trivy is run with --list-all-pkgs. Verified against trivy 0.73.0 on
this repo's own frontend/package-lock.json: 635 packages, 507 flagged Dev,
all 8 vulnerabilities resolving to a package, and every one matching
GitHub Dependabot's `scope: development` for the same lockfile.

"unknown" is a real state throughout, never a synonym for runtime. Rows
predating the column, tools other than trivy, and packages that fail to
resolve all genuinely have no answer, and calling them runtime would
misrank the backlog in the opposite direction from the bug being fixed.
"""
from app.scanners.parsers import (
    SCOPE_DEVELOPMENT,
    SCOPE_RUNTIME,
    SCOPE_UNKNOWN,
    parse_trivy,
)
from app.scanners.runner import TOOL_COMMANDS


def _trivy_output(packages, vulns):
    return {"Results": [{"Target": "package-lock.json", "Packages": packages, "Vulnerabilities": vulns}]}


def test_a_dev_dependency_finding_is_marked_development():
    parsed = parse_trivy(_trivy_output(
        packages=[{"ID": "vitest@2.1.9", "Name": "vitest", "Dev": True}],
        vulns=[{"VulnerabilityID": "CVE-2026-47429", "PkgID": "vitest@2.1.9",
                "PkgName": "vitest", "Severity": "CRITICAL"}],
    ))

    assert parsed[0]["dependency_scope"] == SCOPE_DEVELOPMENT


def test_a_runtime_dependency_finding_is_marked_runtime():
    """trivy omits the Dev key for runtime packages rather than setting it
    false, so presence-and-truthy is the test, not equality."""
    parsed = parse_trivy(_trivy_output(
        packages=[{"ID": "next@15.1.0", "Name": "next"}],
        vulns=[{"VulnerabilityID": "CVE-1", "PkgID": "next@15.1.0",
                "PkgName": "next", "Severity": "HIGH"}],
    ))

    assert parsed[0]["dependency_scope"] == SCOPE_RUNTIME


def test_an_unresolvable_package_is_unknown_not_runtime():
    """The failure that matters. If PkgID does not match any package --
    because --list-all-pkgs was dropped, or the ecosystem reports no
    package list -- guessing runtime would quietly promote every finding."""
    parsed = parse_trivy(_trivy_output(
        packages=[],
        vulns=[{"VulnerabilityID": "CVE-1", "PkgID": "mystery@1.0", "Severity": "HIGH"}],
    ))

    assert parsed[0]["dependency_scope"] == SCOPE_UNKNOWN


def test_a_vulnerability_with_no_pkgid_is_unknown():
    parsed = parse_trivy(_trivy_output(
        packages=[{"ID": "x@1", "Dev": True}],
        vulns=[{"VulnerabilityID": "CVE-1", "Severity": "LOW"}],
    ))

    assert parsed[0]["dependency_scope"] == SCOPE_UNKNOWN


def test_mixed_scopes_in_one_result_are_attributed_individually():
    """The realistic case: one lockfile, both kinds. A per-result default
    would flatten this."""
    parsed = parse_trivy(_trivy_output(
        packages=[
            {"ID": "vitest@2.1.9", "Dev": True},
            {"ID": "next@15.1.0"},
        ],
        vulns=[
            {"VulnerabilityID": "CVE-A", "PkgID": "vitest@2.1.9", "Severity": "CRITICAL"},
            {"VulnerabilityID": "CVE-B", "PkgID": "next@15.1.0", "Severity": "HIGH"},
        ],
    ))

    by_cve = {f["cve_id"]: f["dependency_scope"] for f in parsed}
    assert by_cve == {"CVE-A": SCOPE_DEVELOPMENT, "CVE-B": SCOPE_RUNTIME}


def test_misconfiguration_findings_are_unaffected():
    """Trivy misconfigurations are not dependencies and have no scope; the
    column default covers them."""
    parsed = parse_trivy({"Results": [{
        "Target": "Dockerfile",
        "Misconfigurations": [{"ID": "DS002", "Title": "t", "Severity": "HIGH"}],
    }]})

    assert len(parsed) == 1
    assert "dependency_scope" not in parsed[0]


def test_trivy_is_invoked_with_the_package_list():
    """Without --list-all-pkgs trivy emits no Packages, every finding
    resolves to unknown, and the column is inert. This is the one flag the
    whole feature depends on."""
    cmd = TOOL_COMMANDS["trivy"]("/repo")

    assert "--list-all-pkgs" in cmd
    assert "--include-dev-deps" in cmd
    assert cmd[-1] == "/repo"
