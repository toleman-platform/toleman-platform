"""trivy must scan npm devDependencies (#487).

trivy's `fs` scanner skips devDependencies by default. On this repository
that default hid every npm CVE it had: measured against
frontend/package-lock.json, 0 findings without the flag and 8 with it --
1 critical, 2 high, 5 medium -- matching GitHub Dependabot's open alerts
for the same lockfile exactly.

The argument for trivy's default is that dev dependencies do not ship to
production. That is the wrong default for a security product. Build-time
tooling is precisely what supply-chain attacks target, a compromised test
runner executes with CI's credentials, and a scanner that reports nothing
because it never looked is indistinguishable from one that looked and
found nothing -- which is the failure this codebase treats as the serious
one.
"""
from app.scanners.runner import TOOL_COMMANDS


def test_trivy_includes_dev_dependencies():
    cmd = TOOL_COMMANDS["trivy"]("/repo")

    assert "--include-dev-deps" in cmd, (
        "without this flag trivy silently reports 0 npm vulnerabilities on a "
        "lockfile whose dev dependencies carry known CVEs"
    )


def test_trivy_still_scans_for_vulnerabilities_only():
    """The scanner set is deliberate (#244): trivy's default is
    [vuln, secret], and secrets are gitleaks'/noseyparker's job here."""
    cmd = TOOL_COMMANDS["trivy"]("/repo")

    assert "--scanners" in cmd
    assert cmd[cmd.index("--scanners") + 1] == "vuln"


def test_the_repo_path_is_still_the_final_argument():
    """run_tool builds this positionally; a flag appended after the path
    would be parsed by trivy as a second target."""
    assert TOOL_COMMANDS["trivy"]("/repo")[-1] == "/repo"


def test_license_scanning_is_left_alone():
    """trivy-license is a separate tool entry and a separate question.
    Dev-dependency licences are not a compliance obligation the way a
    shipped dependency's are, so it keeps trivy's default."""
    cmd = TOOL_COMMANDS["trivy-license"]("/repo")

    assert "--include-dev-deps" not in cmd
    assert cmd[cmd.index("--scanners") + 1] == "license"
