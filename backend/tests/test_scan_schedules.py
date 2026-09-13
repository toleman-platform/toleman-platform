"""Tests for configurable scheduled scans (issue #306).

Five properties this file exists to hold down, in the order the issue asks
for them:

  1. Due-schedule selection, including the boundaries. "Due" is a
     `<=` comparison against a stored timestamp, so exactly-now and
     one-second-either-side are the cases that break first when someone
     "simplifies" the query.
  2. `last_run_at`/`next_run_at` live in the database, so a restart can
     neither double-fire a schedule that already ran nor skip one that is
     genuinely overdue. This is the whole reason the clock moved out of
     Celery Beat's in-memory schedule state.
  3. A disabled schedule never dispatches anything, at either scope, and is
     never stamped as having run.
  4. Active API scanning is never dispatched at a target that is
     deactivated (nuclei turned off for the `api_scan` surface) or
     unconfigured (no `api_base_url`, or no discovered endpoints). This is
     the safety boundary from #72 holding when a schedule is the caller
     rather than a person.
  5. The shipped default reproduces today's behaviour exactly: full scans
     every 24 hours, active API scanning off.

Dispatch is monkeypatched throughout (`queue_full_scan`/`queue_api_scan`);
what is under test is which schedules fire and against which targets, not
the scan pipeline those two already have their own coverage for
(test_auto_full_scan.py, test_api_scan.py).
"""
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.core import scan_schedules as core
from app.core.time import utcnow
from app.models.models import (
    ApiEndpoint,
    Organization,
    ScanSchedule,
    ScanScheduleType,
    Target,
    Workspace,
    WorkspaceToolConfig,
)
from app.tasks import schedule_tasks


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _make_workspace(session, name="ws") -> Workspace:
    org = Organization(name=f"org-{name}")
    session.add(org)
    session.commit()
    session.refresh(org)
    ws = Workspace(organization_id=org.id, name=name, api_key=f"k-{name}")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    return ws


def _make_target(session, ws, name="repo", **kwargs) -> Target:
    target = Target(
        workspace_id=ws.id,
        name=name,
        repo_url=f"https://github.com/acme/{name}",
        default_branch=kwargs.pop("default_branch", "main"),
        **kwargs,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def _schedule(session, ws, *, scan_type=ScanScheduleType.FULL_SCAN, target=None, **kwargs) -> ScanSchedule:
    row = ScanSchedule(
        workspace_id=ws.id,
        target_id=target.id if target else None,
        scan_type=scan_type,
        **kwargs,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@pytest.fixture()
def no_dispatch(monkeypatch):
    """Both dispatch helpers replaced, so nothing here can reach a real
    Celery broker or scanner. Returns the two mocks."""
    full = MagicMock(return_value=[101])
    api = MagicMock(return_value=202)
    import app.tasks.api_scan_tasks as api_scan_tasks
    import app.tasks.scan_tasks as scan_tasks

    monkeypatch.setattr(scan_tasks, "queue_full_scan", full)
    monkeypatch.setattr(api_scan_tasks, "queue_api_scan", api)
    return full, api


# ---------------------------------------------------------------------------
# 5. The shipped default reproduces today's behaviour
# ---------------------------------------------------------------------------


def test_shipped_default_full_scan_is_on_every_24h():
    """The old hardcoded beat entry was timedelta(hours=24) over every
    target. An install that configures nothing must keep getting exactly
    that; this constant is the only thing standing behind that promise."""
    shipped = core.SHIPPED_DEFAULTS[ScanScheduleType.FULL_SCAN]
    assert shipped.enabled is True
    assert shipped.interval_hours == 24


def test_shipped_default_api_scan_is_off():
    """Active API scanning was never on a schedule before #306; it only ran
    when someone clicked. Shipping it on by default would start probing live
    hosts on the first worker restart after an upgrade, which is a
    network-visible side effect nobody asked for."""
    shipped = core.SHIPPED_DEFAULTS[ScanScheduleType.API_SCAN]
    assert shipped.enabled is False


def test_resolution_with_nothing_configured_is_the_shipped_default(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)

        full = core.resolve_scan_schedule(session, target, ScanScheduleType.FULL_SCAN)
        assert full.enabled is True
        assert full.interval_hours == 24
        assert full.enabled_source == "default"
        assert full.interval_source == "default"
        # Nothing has ever run, and nothing is stored. Both have to read as
        # "unknown/never", not as zero or as an empty string.
        assert full.schedule_id is None
        assert full.last_run_at is None
        assert full.next_run_at is None

        api = core.resolve_scan_schedule(session, target, ScanScheduleType.API_SCAN)
        assert api.enabled is False


def test_unconfigured_workspace_dispatches_full_scans_on_the_24h_default(engine, no_dispatch):
    """End to end for the "changes nothing for an install that configures
    nothing" promise: materialise defaults, jump a day forward, and the same
    every-target full scan the old beat entry produced comes out."""
    full, api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws, "a")
        _make_target(session, ws, "b")

        schedule_tasks.dispatch_due_scan_schedules(session)
        # Nothing is due yet: the materialised default sits one full
        # interval out, preserving Beat's own first-tick behaviour.
        assert full.call_count == 0

        for row in session.exec(select(ScanSchedule)).all():
            row.next_run_at = utcnow() - timedelta(seconds=1)
            session.add(row)
        session.commit()

        summary = schedule_tasks.dispatch_due_scan_schedules(session)

        assert full.call_count == 2
        assert {c.args[1].name for c in full.call_args_list} == {"a", "b"}
        # API scanning is off by default, so its (also due) row never fires.
        assert api.call_count == 0
        assert summary["scans_dispatched"] == 2


# ---------------------------------------------------------------------------
# 1. Due-schedule selection, including the boundaries
# ---------------------------------------------------------------------------


def test_due_schedules_includes_a_schedule_due_exactly_now(engine):
    """The inclusive boundary. An exclusive `<` would make a schedule whose
    due time lands exactly on a tick slip to the next one, and whether that
    ever happens would depend on clock resolution -- a bug that only shows
    up in production and never in a test written with round numbers."""
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        _schedule(session, ws, next_run_at=now)

        assert len(core.due_schedules(session, now)) == 1


def test_due_schedules_includes_a_schedule_one_second_overdue(engine):
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        _schedule(session, ws, next_run_at=now - timedelta(seconds=1))

        assert len(core.due_schedules(session, now)) == 1


def test_due_schedules_excludes_a_schedule_one_second_early(engine):
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        _schedule(session, ws, next_run_at=now + timedelta(seconds=1))

        assert core.due_schedules(session, now) == []


def test_due_schedules_treats_a_null_next_run_at_as_due(engine):
    """Every write path sets next_run_at, so NULL only happens if something
    wrote a row without going through this module. "Run it on the next tick"
    is the safe reading of a row whose clock was never set; the alternative
    is a schedule that is silently never due."""
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        _schedule(session, ws, next_run_at=None)

        assert len(core.due_schedules(session, now)) == 1


def test_due_schedules_excludes_a_disabled_row_even_when_overdue(engine):
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        _schedule(session, ws, enabled=False, next_run_at=now - timedelta(days=7))

        assert core.due_schedules(session, now) == []


def test_a_target_row_is_due_on_its_own_interval_not_the_workspaces(engine):
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)
        _schedule(session, ws, interval_hours=24, next_run_at=now + timedelta(hours=20))
        own = _schedule(session, ws, target=target, interval_hours=1, next_run_at=now - timedelta(minutes=1))

        due = core.due_schedules(session, now)
        assert [row.id for row in due] == [own.id]


# ---------------------------------------------------------------------------
# Inheritance: field-level, NULL means inherit
# ---------------------------------------------------------------------------


def test_target_row_inherits_the_workspace_interval_when_it_only_sets_enabled(engine):
    """The refinement over enforcement_mode's single-scalar inheritance.
    Pausing one target must not silently reset its cadence to the shipped
    24h, because re-enabling it would then quietly be a different schedule
    from the one that was paused."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)
        _schedule(session, ws, interval_hours=6)
        _schedule(session, ws, target=target, enabled=False)

        resolved = core.resolve_scan_schedule(session, target, ScanScheduleType.FULL_SCAN)
        assert resolved.enabled is False
        assert resolved.enabled_source == "target"
        assert resolved.interval_hours == 6
        assert resolved.interval_source == "workspace"


def test_workspace_row_overrides_the_shipped_default(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)
        _schedule(session, ws, interval_hours=4)

        resolved = core.resolve_scan_schedule(session, target, ScanScheduleType.FULL_SCAN)
        assert resolved.interval_hours == 4
        assert resolved.interval_source == "workspace"
        assert resolved.enabled_source == "default"


def test_a_disabled_schedule_reports_no_next_run(engine):
    """A paused schedule with a confident future "next run" next to it is a
    lie whichever half the reader believes."""
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)
        _schedule(session, ws, enabled=False, next_run_at=now + timedelta(hours=3))

        resolved = core.resolve_scan_schedule(session, target, ScanScheduleType.FULL_SCAN)
        assert resolved.enabled is False
        assert resolved.next_run_at is None


def test_workspace_default_does_not_cover_a_target_with_its_own_row(engine):
    """Otherwise a target given a faster cadence would keep getting the
    workspace's too, and be scanned on both clocks."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        covered = _make_target(session, ws, "covered")
        overridden = _make_target(session, ws, "overridden")
        ws_row = _schedule(session, ws)
        _schedule(session, ws, target=overridden, interval_hours=2)

        names = {t.name for t in core.targets_covered_by(session, ws_row)}
        assert names == {"covered"}


def test_a_workspace_default_never_reaches_another_workspaces_targets(engine):
    with Session(engine) as session:
        ws_a = _make_workspace(session, "a")
        ws_b = _make_workspace(session, "b")
        _make_target(session, ws_a, "mine")
        _make_target(session, ws_b, "theirs")
        row = _schedule(session, ws_a)

        assert [t.name for t in core.targets_covered_by(session, row)] == ["mine"]


def test_interval_validation_rejects_zero_and_accepts_none(engine):
    assert core.validate_interval_hours(None) is None
    assert core.validate_interval_hours(1) == 1
    with pytest.raises(core.ScanScheduleError):
        core.validate_interval_hours(0)
    with pytest.raises(core.ScanScheduleError):
        core.validate_interval_hours(core.MAX_INTERVAL_HOURS + 1)


# ---------------------------------------------------------------------------
# 2. Restart safety: last_run_at/next_run_at prevent double-fire and skip
# ---------------------------------------------------------------------------


def test_dispatch_stamps_last_run_at_and_pushes_next_run_at_forward(engine, no_dispatch):
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws)
        row = _schedule(session, ws, interval_hours=6, next_run_at=utcnow() - timedelta(minutes=1))

        schedule_tasks.dispatch_due_scan_schedules(session)
        session.refresh(row)

        assert full.call_count == 1
        assert row.last_run_at is not None
        assert row.last_dispatched_count == 1
        assert row.next_run_at > utcnow() + timedelta(hours=5)


def test_a_restart_does_not_double_fire_a_schedule_that_just_ran(engine, no_dispatch):
    """The restart case in full: dispatch, then run the whole pass again the
    way a redelivered beat task or a freshly-booted worker would. The second
    pass must find nothing due, because the clock is in the database rather
    than in Beat's in-memory schedule state."""
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws)
        _schedule(session, ws, interval_hours=24, next_run_at=utcnow() - timedelta(minutes=1))

        schedule_tasks.dispatch_due_scan_schedules(session)
        assert full.call_count == 1

        # Simulated restart: nothing in memory carries over, the rows do.
        schedule_tasks.dispatch_due_scan_schedules(session)
        schedule_tasks.dispatch_due_scan_schedules(session)

        assert full.call_count == 1


def test_a_long_outage_fires_once_not_once_per_missed_interval(engine, no_dispatch):
    """next_run_at is recomputed from now, not advanced by one interval at a
    time. A worker down for two days must not replay 48 missed hourly runs
    into the scan queue the moment it reconnects -- that catch-up storm is
    exactly the bulk-dispatch shape #229 describes."""
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws)
        row = _schedule(session, ws, interval_hours=1, next_run_at=utcnow() - timedelta(days=2))

        schedule_tasks.dispatch_due_scan_schedules(session)
        session.refresh(row)

        assert full.call_count == 1
        assert row.next_run_at > utcnow()


def test_a_schedule_that_never_fired_keeps_last_run_at_null(engine, no_dispatch):
    """The honesty property. A fresh install spends its first interval in
    this state, and the UI has to be able to tell it apart from "fired, and
    there was nothing to do"."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws)

        schedule_tasks.dispatch_due_scan_schedules(session)

        rows = session.exec(select(ScanSchedule)).all()
        assert rows, "the dispatcher should have materialised workspace defaults"
        assert all(row.last_run_at is None for row in rows)
        assert all(row.next_run_at is not None for row in rows)


def test_materialising_defaults_is_idempotent(engine, no_dispatch):
    with Session(engine) as session:
        ws = _make_workspace(session)

        created_first = core.ensure_workspace_default_rows(session)
        created_again = core.ensure_workspace_default_rows(session)

        assert len(created_first) == len(list(ScanScheduleType))
        assert created_again == []
        assert len(session.exec(select(ScanSchedule)).all()) == len(list(ScanScheduleType))
        # Materialised rows store NULLs, not a copy of today's shipped
        # values: they are a place to record runs, not an operator decision.
        assert all(row.enabled is None and row.interval_hours is None for row in created_first)
        assert ws.id == created_first[0].workspace_id


def test_a_failing_target_does_not_stop_the_rest_of_the_schedule(engine, monkeypatch):
    """Same "one bad target can't block another" property the old
    run_scheduled_full_scans loop already had."""
    import app.tasks.scan_tasks as scan_tasks

    calls = {"n": 0}

    def _flaky(session, target):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return [1]

    monkeypatch.setattr(scan_tasks, "queue_full_scan", _flaky)

    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws, "a")
        _make_target(session, ws, "b")
        row = _schedule(session, ws, next_run_at=utcnow() - timedelta(minutes=1))

        summary = schedule_tasks.dispatch_due_scan_schedules(session)
        session.refresh(row)

        assert calls["n"] == 2
        assert summary["scans_dispatched"] == 1
        assert row.last_dispatched_count == 1


def test_a_schedule_whose_target_was_deleted_is_a_silent_noop(engine, no_dispatch):
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)
        row = _schedule(session, ws, target=target, next_run_at=utcnow() - timedelta(minutes=1))
        session.delete(target)
        session.commit()

        schedule_tasks.dispatch_due_scan_schedules(session)
        session.refresh(row)

        full.assert_not_called()
        # It still fired -- and honestly reports that it dispatched nothing.
        assert row.last_run_at is not None
        assert row.last_dispatched_count == 0


# ---------------------------------------------------------------------------
# 3. A disabled schedule never dispatches
# ---------------------------------------------------------------------------


def test_a_disabled_workspace_schedule_dispatches_nothing(engine, no_dispatch):
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws)
        row = _schedule(session, ws, enabled=False, next_run_at=utcnow() - timedelta(days=1))

        schedule_tasks.dispatch_due_scan_schedules(session)
        session.refresh(row)

        full.assert_not_called()
        # And is never stamped as having run, so "Never run" stays true.
        assert row.last_run_at is None


def test_a_disabled_target_schedule_dispatches_nothing_for_that_target(engine, no_dispatch):
    """Both halves at once: the disabled target is skipped AND is not
    silently picked back up by the workspace default it overrides."""
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws, "scanned")
        paused = _make_target(session, ws, "paused")
        _schedule(session, ws, next_run_at=utcnow() - timedelta(minutes=1))
        _schedule(session, ws, target=paused, enabled=False, next_run_at=utcnow() - timedelta(minutes=1))

        schedule_tasks.dispatch_due_scan_schedules(session)

        assert [c.args[1].name for c in full.call_args_list] == ["scanned"]


# ---------------------------------------------------------------------------
# 4. Active API scanning: never probe a deactivated or unconfigured target
# ---------------------------------------------------------------------------


def _api_schedule_due(session, ws, target=None):
    return _schedule(
        session,
        ws,
        scan_type=ScanScheduleType.API_SCAN,
        target=target,
        enabled=True,
        next_run_at=utcnow() - timedelta(minutes=1),
    )


def test_scheduled_api_scan_reaches_a_configured_target(engine, no_dispatch):
    _full, api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        _api_schedule_due(session, ws)

        schedule_tasks.dispatch_due_scan_schedules(session)

        api.assert_called_once()
        assert api.call_args.args[1].id == target.id


def test_scheduled_api_scan_never_probes_a_target_with_no_api_base_url(engine, monkeypatch):
    """Target.api_base_url is the ONLY source of a scan host (see
    app.core.api_scan_targets). A schedule must never infer one from
    repo_url or from a discovered endpoint's own text."""
    import app.tasks.api_scan_tasks as api_scan_tasks

    run = MagicMock()
    monkeypatch.setattr(api_scan_tasks.run_api_scan, "delay", run)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url=None)
        session.add(ApiEndpoint(
            target_id=target.id, branch="main", framework="fastapi",
            method="GET", route="/v1/users", file_path="app/main.py", line=1,
        ))
        session.commit()

        assert api_scan_tasks.queue_api_scan(session, target) is None
        run.assert_not_called()


def test_scheduled_api_scan_never_probes_when_nuclei_is_disabled_for_the_surface(engine, monkeypatch):
    """A deactivated tool stays deactivated when a schedule is what is
    asking, not just when a person clicks the button (#232/#75)."""
    import app.tasks.api_scan_tasks as api_scan_tasks

    run = MagicMock()
    monkeypatch.setattr(api_scan_tasks.run_api_scan, "delay", run)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        session.add(ApiEndpoint(
            target_id=target.id, branch="main", framework="fastapi",
            method="GET", route="/v1/users", file_path="app/main.py", line=1,
        ))
        session.add(WorkspaceToolConfig(workspace_id=ws.id, tool="nuclei", api_scan=False))
        session.commit()

        assert api_scan_tasks.queue_api_scan(session, target) is None
        run.assert_not_called()


def test_scheduled_api_scan_never_probes_a_target_with_no_discovered_endpoints(engine, monkeypatch):
    """Probing zero URLs is not a scan, and recording one would be a
    fabricated clean result."""
    import app.tasks.api_scan_tasks as api_scan_tasks

    run = MagicMock()
    monkeypatch.setattr(api_scan_tasks.run_api_scan, "delay", run)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")

        assert api_scan_tasks.queue_api_scan(session, target) is None
        run.assert_not_called()
        # And no Scan row was created, so the target's history does not grow
        # a permanently-red entry nobody asked for.
        from app.models.models import Scan

        assert session.exec(select(Scan).where(Scan.target_id == target.id)).all() == []


def test_scheduled_api_scan_dispatches_through_the_normal_queue(engine, monkeypatch):
    """Routed through run_api_scan.delay() exactly like the interactive
    POST /api/api-scan/{id} path, onto the same "scans" queue; no separate
    scheduled-scan pipe and therefore no added concurrency (#229)."""
    import app.tasks.api_scan_tasks as api_scan_tasks
    from app.models.models import Scan

    run = MagicMock()
    monkeypatch.setattr(api_scan_tasks.run_api_scan, "delay", run)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        session.add(ApiEndpoint(
            target_id=target.id, branch="main", framework="fastapi",
            method="GET", route="/v1/users", file_path="app/main.py", line=1,
        ))
        session.commit()

        scan_id = api_scan_tasks.queue_api_scan(session, target)

        assert scan_id is not None
        run.assert_called_once()
        assert run.call_args.kwargs["scan_id"] == scan_id
        assert run.call_args.kwargs["endpoint_ids"] is None
        scan = session.get(Scan, scan_id)
        assert scan.tool == "api-scan"
        assert scan.branch == "main"


# ---------------------------------------------------------------------------
# Beat wiring
# ---------------------------------------------------------------------------


def test_the_dispatcher_is_the_beat_entry():
    from app.tasks.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["dispatch-due-scan-schedules"]
    assert entry["task"] == "app.tasks.schedule_tasks.dispatch_due_scan_schedules_task"


def test_the_old_hardcoded_full_scan_entry_is_gone():
    """Leaving it alongside the dispatcher would fan a full scan out across
    every target from two independent clocks -- the duplicated bulk dispatch
    #229 warns about."""
    from app.tasks.celery_app import celery_app

    assert "run-scheduled-full-scans" not in celery_app.conf.beat_schedule


def test_the_dispatcher_ticks_far_more_often_than_any_cadence():
    """The tick is the resolution at which a schedule can come due, not how
    often scans run. It has to be well under the minimum configurable
    interval or an hourly schedule silently becomes something else."""
    from app.tasks.celery_app import SCHEDULE_DISPATCH_INTERVAL

    assert SCHEDULE_DISPATCH_INTERVAL < timedelta(hours=core.MIN_INTERVAL_HOURS)
