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


# --- scoring (#500 item 3) -------------------------------------------

from app.core.scoring import (  # noqa: E402
    BASELINE_WEIGHTS,
    DEPENDENCY_SCOPE_POINTS,
    compute_priority_score,
    compute_score_breakdown,
)
from app.models.models import ScoringSignal, Severity  # noqa: E402


def _zeroed(**overrides):
    return {**{s: 0.0 for s in ScoringSignal}, **overrides}


def test_the_slot_ships_switched_off():
    """House convention for every signal #201 added: configuration that
    exists and works, not behaviour anyone gets without asking. An install
    that configures nothing must score exactly as it did before."""
    assert BASELINE_WEIGHTS[ScoringSignal.DEPENDENCY_SCOPE] == 0.0

    with_scope = compute_priority_score(Severity.HIGH, 3, dependency_scope="runtime")
    without = compute_priority_score(Severity.HIGH, 3)

    assert with_scope == without


def test_runtime_scope_lifts_the_score_when_the_weight_is_turned_up():
    weights = _zeroed(**{ScoringSignal.DEPENDENCY_SCOPE: 1.0})

    runtime = compute_priority_score(Severity.HIGH, 3, dependency_scope="runtime", weights=weights)
    baseline = compute_priority_score(Severity.HIGH, 3, weights=_zeroed())

    assert runtime - baseline == DEPENDENCY_SCOPE_POINTS


def test_development_scope_gets_no_uplift_and_no_penalty():
    """An uplift for shipping, not a penalty for not shipping. A dev
    dependency still needs fixing -- a compromised build tool runs with
    CI's credentials -- it just does not outrank a deployed one."""
    weights = _zeroed(**{ScoringSignal.DEPENDENCY_SCOPE: 1.0})

    development = compute_priority_score(Severity.HIGH, 3, dependency_scope="development", weights=weights)
    baseline = compute_priority_score(Severity.HIGH, 3, weights=_zeroed())

    assert development == baseline


def test_unknown_scope_is_never_penalised():
    """The property that makes this safe to switch on with a backlog full
    of pre-existing findings: every row predating the column reads
    "unknown", and unknown must land exactly where the base formula put
    it. Otherwise turning the dial up re-ranks history on data nobody
    collected."""
    weights = _zeroed(**{ScoringSignal.DEPENDENCY_SCOPE: 1.0})

    for value in ("unknown", None):
        scored = compute_priority_score(Severity.HIGH, 3, dependency_scope=value, weights=weights)
        assert scored == compute_priority_score(Severity.HIGH, 3, weights=_zeroed())


def test_the_breakdown_explains_each_state():
    """The Admin surface shows why a score is what it is, so "established"
    has to distinguish "we know it is a build dependency" from "we have no
    idea" -- both contribute zero points but they are not the same claim."""
    weights = _zeroed(**{ScoringSignal.DEPENDENCY_SCOPE: 1.0})

    def contribution(scope):
        breakdown = compute_score_breakdown(Severity.HIGH, 3, dependency_scope=scope, weights=weights)
        return breakdown.contribution(ScoringSignal.DEPENDENCY_SCOPE)

    runtime = contribution("runtime")
    assert runtime.established is True
    assert runtime.points == DEPENDENCY_SCOPE_POINTS

    development = contribution("development")
    assert development.established is True
    assert development.points == 0

    unknown = contribution("unknown")
    assert unknown.established is False
    assert unknown.points == 0


# --- the findings filter (#500 item 4) -------------------------------

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

import app.api.deps as deps_module  # noqa: E402
from app.api.deps import get_session  # noqa: E402
from app.core.security import create_session_token, hash_password  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models.models import (  # noqa: E402
    Finding,
    Organization,
    Target,
    User,
    UserRole,
    Workspace,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override():
        with Session(engine) as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = override
    original = deps_module.engine
    deps_module.engine = engine
    c = TestClient(fastapi_app)
    yield c
    fastapi_app.dependency_overrides.clear()
    deps_module.engine = original


def _seed(engine):
    with Session(engine) as session:
        org = Organization(name="Acme")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/a/b")
        session.add(t)
        session.commit()
        session.refresh(t)
        for idx, scope in enumerate(("runtime", "development", "unknown")):
            session.add(Finding(
                target_id=t.id, dedup_hash=f"h{idx}", tool="trivy",
                rule_id=f"CVE-{idx}", title=f"f{idx}", file_path="package-lock.json",
                severity=Severity.HIGH, dependency_scope=scope,
            ))
        session.commit()
        user = User(email="a@example.com", name="A",
                    password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        return create_session_token(user.id, user.token_version)


def test_findings_can_be_filtered_to_runtime_only(client, engine):
    """The click that makes the scope worth recording: during triage, show
    only what actually ships."""
    client.cookies.set("toleman_session", _seed(engine))

    res = client.get("/api/findings?dependency_scope=runtime")

    assert res.status_code == 200
    scopes = [f["rule_id"] for f in res.json()["items"]]
    assert scopes == ["CVE-0"]


def test_the_filter_is_multi_select(client, engine):
    """"runtime" plus "unknown" is the honest way to ask "anything that
    might ship" while the backlog still holds rows that predate the
    column."""
    client.cookies.set("toleman_session", _seed(engine))

    res = client.get("/api/findings?dependency_scope=runtime&dependency_scope=unknown")

    assert sorted(f["rule_id"] for f in res.json()["items"]) == ["CVE-0", "CVE-2"]


def test_no_filter_returns_every_scope(client, engine):
    """Absence of the parameter must not imply a default scope."""
    client.cookies.set("toleman_session", _seed(engine))

    res = client.get("/api/findings")

    assert len(res.json()["items"]) == 3


def test_an_unknown_scope_value_is_rejected(client, engine):
    client.cookies.set("toleman_session", _seed(engine))

    assert client.get("/api/findings?dependency_scope=nonsense").status_code == 422
