"""Tests for app.core.remediation_autofix.sweep_auto_raise_prs (#247
follow-up): the beat-scheduled sweep that raises PRs for every opted-in
target's unaddressed Fix Plan packages, no user interaction involved.

Mocks raise_package_fix_pr at the module boundary throughout (the actual
GitHub-write behavior and the "package-level version, not per-finding
lowest" property are already pinned down directly in test_autofix.py) so
these can focus purely on the sweep's own logic: who gets swept, what
counts as "already raised", and that one target's failure doesn't take
down the rest.
"""
import json

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.core.remediation_autofix as remediation_autofix
import pytest
from app.core.autofix import AutofixError
from app.models.models import (
    CveEnrichment,
    Finding,
    FindingState,
    Organization,
    RemediationFixPr,
    Severity,
    Target,
    Workspace,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _target(engine, auto_raise=True, deactivated_at=None, deleted_at=None, name="t") -> int:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(
            workspace_id=ws.id, name=name, repo_url=f"https://github.com/a/{name}",
            auto_raise_fix_prs=auto_raise, deactivated_at=deactivated_at, deleted_at=deleted_at,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


def _finding_with_fix(engine, target_id, cve_id, package, fixed_version) -> int:
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, tool="trivy", rule_id=cve_id, title=f"{cve_id} in {package}",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id=cve_id,
            state=FindingState.OPEN, dedup_hash=f"hash-{cve_id}-{target_id}",
        )
        session.add(f)
        session.add(CveEnrichment(
            cve_id=cve_id, osv_found=True,
            fixed_versions=json.dumps([{"package": package, "ecosystem": "PyPI", "fixed": fixed_version}]),
        ))
        session.commit()
        session.refresh(f)
        return f.id


def _record_prior_raise(engine, target_id, package, upgrade_to, finding_ids: list[int]):
    with Session(engine) as session:
        session.add(RemediationFixPr(
            target_id=target_id, package=package, upgrade_to=upgrade_to,
            finding_ids=json.dumps(finding_ids),
            pr_url="https://github.com/a/t/pull/1", pr_number=1, branch="toleman/fix-pkg-1",
            raised_by="sweep",
        ))
        session.commit()


def test_sweep_only_touches_opted_in_targets(engine, monkeypatch):
    opted_in = _target(engine, auto_raise=True, name="in")
    opted_out = _target(engine, auto_raise=False, name="out")
    _finding_with_fix(engine, opted_in, "CVE-2024-1", "starlette", "0.40.0")
    _finding_with_fix(engine, opted_out, "CVE-2024-2", "axios", "1.7.4")

    raised_for = []

    def fake_raise(session, target, plan, raised_by):
        raised_for.append((target.id, plan["package"]))
        return {"pr_url": "https://github.com/a/t/pull/9", "pr_number": 9, "branch": "b"}

    monkeypatch.setattr(remediation_autofix, "raise_package_fix_pr", fake_raise)

    with Session(engine) as session:
        summary = remediation_autofix.sweep_auto_raise_prs(session)

    assert raised_for == [(opted_in, "starlette")]
    assert summary["targets_opted_in"] == 1
    assert summary["prs_raised"] == 1


def test_sweep_excludes_deactivated_and_deleted_targets(engine, monkeypatch):
    from app.core.time import utcnow

    active = _target(engine, auto_raise=True, name="active")
    deactivated = _target(engine, auto_raise=True, deactivated_at=utcnow(), name="deactivated")
    deleted = _target(engine, auto_raise=True, deleted_at=utcnow(), name="deleted")
    for tid, name in [(active, "a"), (deactivated, "b"), (deleted, "c")]:
        _finding_with_fix(engine, tid, f"CVE-2024-{name}", "starlette", "0.40.0")

    raised_for = []
    monkeypatch.setattr(
        remediation_autofix, "raise_package_fix_pr",
        lambda session, target, plan, raised_by: raised_for.append(target.id)
        or {"pr_url": "u", "pr_number": 1, "branch": "b"},
    )

    with Session(engine) as session:
        summary = remediation_autofix.sweep_auto_raise_prs(session)

    assert raised_for == [active]
    assert summary["targets_opted_in"] == 1


def test_sweep_skips_a_package_already_covered_by_a_prior_raise(engine, monkeypatch):
    target_id = _target(engine, auto_raise=True)
    finding_id = _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")
    _record_prior_raise(engine, target_id, "starlette", "0.40.0", [finding_id])

    mock_raise = _never_called()
    monkeypatch.setattr(remediation_autofix, "raise_package_fix_pr", mock_raise.fn)

    with Session(engine) as session:
        summary = remediation_autofix.sweep_auto_raise_prs(session)

    assert mock_raise.calls == []
    assert summary["prs_skipped_already_raised"] == 1
    assert summary["prs_raised"] == 0


def test_sweep_raises_for_a_genuinely_new_package_even_when_another_is_covered(engine, monkeypatch):
    """One package already has a PR on record; a second, unrelated package
    in the same target's plan does not -- the second must still get raised,
    proving the skip is scoped per-package, not per-target."""
    target_id = _target(engine, auto_raise=True)
    covered_finding_id = _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.40.0")
    _finding_with_fix(engine, target_id, "CVE-2024-2", "axios", "1.7.4")
    _record_prior_raise(engine, target_id, "starlette", "0.40.0", [covered_finding_id])

    raised_packages = []
    monkeypatch.setattr(
        remediation_autofix, "raise_package_fix_pr",
        lambda session, target, plan, raised_by: raised_packages.append(plan["package"])
        or {"pr_url": "u", "pr_number": 1, "branch": "b"},
    )

    with Session(engine) as session:
        summary = remediation_autofix.sweep_auto_raise_prs(session)

    assert raised_packages == ["axios"]
    assert summary["prs_raised"] == 1
    assert summary["prs_skipped_already_raised"] == 1


def test_sweep_raises_again_when_a_new_cve_lands_on_an_already_covered_package(engine, monkeypatch):
    """A prior PR covered finding A on `starlette`; a second, later finding
    B lands on the SAME package. B is not a subset of the covered set, so
    this is genuinely new and must be raised -- not silently absorbed into
    "already addressed"."""
    target_id = _target(engine, auto_raise=True)
    old_finding_id = _finding_with_fix(engine, target_id, "CVE-2024-1", "starlette", "0.39.0")
    _record_prior_raise(engine, target_id, "starlette", "0.39.0", [old_finding_id])
    _finding_with_fix(engine, target_id, "CVE-2024-2", "starlette", "0.40.0")

    raised_packages = []
    monkeypatch.setattr(
        remediation_autofix, "raise_package_fix_pr",
        lambda session, target, plan, raised_by: raised_packages.append(plan["package"])
        or {"pr_url": "u", "pr_number": 1, "branch": "b"},
    )

    with Session(engine) as session:
        summary = remediation_autofix.sweep_auto_raise_prs(session)

    assert raised_packages == ["starlette"]
    assert summary["prs_raised"] == 1
    assert summary["prs_skipped_already_raised"] == 0


def test_one_targets_autofix_error_does_not_stop_the_sweep_for_the_next_target(engine, monkeypatch):
    failing = _target(engine, auto_raise=True, name="failing")
    healthy = _target(engine, auto_raise=True, name="healthy")
    _finding_with_fix(engine, failing, "CVE-2024-1", "starlette", "0.40.0")
    _finding_with_fix(engine, healthy, "CVE-2024-2", "axios", "1.7.4")

    def fake_raise(session, target, plan, raised_by):
        if target.id == failing:
            raise AutofixError("no GitHub App installed")
        return {"pr_url": "https://github.com/a/t/pull/1", "pr_number": 1, "branch": "b"}

    monkeypatch.setattr(remediation_autofix, "raise_package_fix_pr", fake_raise)

    with Session(engine) as session:
        summary = remediation_autofix.sweep_auto_raise_prs(session)

    assert summary["targets_opted_in"] == 2
    assert summary["prs_raised"] == 1
    assert summary["prs_failed"] == 1


class _never_called:
    def __init__(self):
        self.calls = []

    def fn(self, *a, **k):
        self.calls.append((a, k))
        raise AssertionError("raise_package_fix_pr must not be called for an already-covered package")
