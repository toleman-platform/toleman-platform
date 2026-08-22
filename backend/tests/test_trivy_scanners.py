"""trivy's `--scanners` selection (#244 benchmarking, 2026-08-22).

trivy fs defaults to [vuln, secret], not [vuln, misconfig]. The secret
scanner walks every file in the target and its result was never consumed --
parsers.parse_trivy only reads Vulnerabilities and Misconfigurations from
the JSON -- so it was pure wasted work (measured 22x on a venv-inclusive
checkout, 3.5x on a real multi-ecosystem repo). Pinning to `--scanners vuln`
removes that waste with zero change to the findings this codebase actually
parses.
"""
from app.scanners import runner


def test_trivy_pins_scanners_to_vuln_only():
    cmd = runner.TOOL_COMMANDS["trivy"]("/some/repo")
    assert "--scanners" in cmd
    idx = cmd.index("--scanners")
    assert cmd[idx + 1] == "vuln"


def test_trivy_license_and_sbom_entries_are_unaffected():
    # trivy-license already pins its own --scanners license; trivy-sbom's
    # CycloneDX component enumeration doesn't depend on the vuln/secret
    # scanner selection at all. Neither should gain "--scanners vuln".
    license_cmd = runner.TOOL_COMMANDS["trivy-license"]("/some/repo")
    assert "--scanners" in license_cmd
    assert license_cmd[license_cmd.index("--scanners") + 1] == "license"

    sbom_cmd = runner.TOOL_COMMANDS["trivy-sbom"]("/some/repo")
    assert "--scanners" not in sbom_cmd
