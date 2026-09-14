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
  4. Active API scanning is never dispatched at a target it must not probe:
     one the operator deactivated, one whose workspace has nuclei turned off
     for the `api_scan` surface, one with no `api_base_url`, or one with no
     discovered endpoints. That is the safety boundary from #72 holding when
     a schedule is the caller rather than a person, and every refusal has to
     be *reportable* as well as enforced -- an armed schedule that silently
     does nothing forever is the failure this feature would otherwise add.
  5. The shipped default reproduces today's behaviour exactly: full scans
     every 24 hours, active API scanning off.

Dispatch is monkeypatched throughout (`queue_full_scan`/`queue_api_scan`);
what is under test is which schedules fire and against which targets, not
the scan pipeline those two already have their own coverage for
(test_auto_full_scan.py, test_api_scan.py).
"""
import ast
import inspect
import textwrap
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy.exc import IntegrityError
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


# ---------------------------------------------------------------------------
# Claiming: the claim-before-dispatch ordering is not enough on its own
#
# due_schedules materialises the whole list at the top of a pass, but a row
# is only claimed when the loop reaches it -- after every earlier row has
# finished fanning out, which for a platform-wide scan is minutes. These
# exercise that window. The sequential-restart tests above cannot: moving
# the claim to *after* the fan-out leaves every one of them green.
#
# A caveat these state rather than paper over: SQLite with StaticPool gives
# every Session the same underlying connection, so "two workers" here is
# sequencing, not true parallelism. What that still pins down is the
# property the real race depends on -- the due-ness predicate is
# re-evaluated by the database at write time, so a second caller holding a
# row it read while due cannot claim it again.
# ---------------------------------------------------------------------------


def test_claiming_a_due_schedule_twice_only_succeeds_once(engine):
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        row = _schedule(session, ws, interval_hours=6, next_run_at=now - timedelta(minutes=1))

        with Session(engine) as other:
            same_row = other.get(ScanSchedule, row.id)

            assert core.claim_due_schedule(session, row, now) is True
            # The second caller read the row while it was still due.
            assert core.claim_due_schedule(other, same_row, now) is False


def test_claiming_clears_the_previous_dispatch_count(engine):
    """last_dispatched_count is written after the fan-out, so a crash
    mid-pass would otherwise leave the previous pass's count sitting next to
    this pass's fresh last_run_at -- a confident report of something that
    never finished. NULL means "not known for this run", which is true."""
    now = utcnow()
    with Session(engine) as session:
        ws = _make_workspace(session)
        row = _schedule(
            session, ws, next_run_at=now - timedelta(minutes=1),
            last_run_at=now - timedelta(days=1), last_dispatched_count=7,
        )

        assert core.claim_due_schedule(session, row, now) is True
        session.refresh(row)

        assert row.last_dispatched_count is None
        assert row.last_run_at == now


def test_an_overlapping_pass_mid_fanout_does_not_re_dispatch(engine, monkeypatch):
    """The regression test for claim-before-dispatch.

    A second complete pass starts *while the first is still fanning out*,
    which is the window sequential passes never reproduce. With the claim
    taken first, the inner pass finds nothing due and every target is
    scanned exactly once. Move the claim to after the fan-out and the inner
    pass sees the row still due and scans everything a second time.
    """
    import app.tasks.scan_tasks as scan_tasks

    dispatched: list[str] = []
    reentered = {"done": False}

    def _queue(session, target):
        dispatched.append(target.name)
        # Re-enter exactly once, from inside the first target's dispatch,
        # i.e. with the pass half-finished.
        if not reentered["done"]:
            reentered["done"] = True
            with Session(engine) as nested:
                schedule_tasks.dispatch_due_scan_schedules(nested)
        return [1]

    monkeypatch.setattr(scan_tasks, "queue_full_scan", _queue)

    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws, "a")
        _make_target(session, ws, "b")
        _schedule(session, ws, interval_hours=24, next_run_at=utcnow() - timedelta(minutes=1))

        schedule_tasks.dispatch_due_scan_schedules(session)

    assert sorted(dispatched) == ["a", "b"], (
        f"each target must be dispatched exactly once per cycle, got {dispatched}"
    )


def test_a_schedule_claimed_after_selection_is_skipped_not_dispatched(engine, no_dispatch, monkeypatch):
    """The same window from the other side: the row was genuinely due when
    this pass selected it, and somebody else claimed it before this pass
    reached it. That is a normal outcome to count, not an error to log."""
    full, _api = no_dispatch
    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws)
        row = _schedule(session, ws, next_run_at=utcnow() - timedelta(minutes=1))

        def _stale_due(s, now):
            with Session(engine) as other:
                core.claim_due_schedule(other, other.get(ScanSchedule, row.id), now)
            return [row]

        monkeypatch.setattr(schedule_tasks, "due_schedules", _stale_due)

        summary = schedule_tasks.dispatch_due_scan_schedules(session)

        full.assert_not_called()
        assert summary["already_claimed"] == 1
        assert summary["schedules_fired"] == 0


# ---------------------------------------------------------------------------
# Duplicate workspace-default rows
#
# A second target_id-NULL row for the same (workspace, scan type) would come
# due alongside the first, cover every target in the workspace, and double
# every cycle's dispatch forever -- invisibly, because every read path takes
# .first(). The UniqueConstraint cannot stop it (Postgres treats NULL as
# distinct), so a partial unique index does.
# ---------------------------------------------------------------------------


def test_a_second_workspace_default_row_is_rejected_by_the_database(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        _schedule(session, ws, scan_type=ScanScheduleType.FULL_SCAN)

        session.add(
            ScanSchedule(workspace_id=ws.id, target_id=None, scan_type=ScanScheduleType.FULL_SCAN)
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_the_partial_index_still_allows_a_target_row_alongside_the_default(engine):
    """The index is partial for a reason: it must constrain only the
    workspace-default rows. A target override for the same scan type is a
    different, legitimate row."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)
        _schedule(session, ws, scan_type=ScanScheduleType.FULL_SCAN)
        _schedule(session, ws, scan_type=ScanScheduleType.FULL_SCAN, target=target)

        assert len(session.exec(select(ScanSchedule)).all()) == 2


def test_each_workspace_gets_its_own_default(engine):
    with Session(engine) as session:
        ws_a = _make_workspace(session, "a")
        ws_b = _make_workspace(session, "b")
        _schedule(session, ws_a, scan_type=ScanScheduleType.FULL_SCAN)
        _schedule(session, ws_b, scan_type=ScanScheduleType.FULL_SCAN)

        assert len(session.exec(select(ScanSchedule)).all()) == 2


def test_seeding_survives_losing_the_insert_race(engine, monkeypatch):
    """ensure_workspace_default_rows is lookup-then-insert and runs
    unattended on every tick, so the race is real rather than theoretical.
    The loser must roll back and carry on, not crash the pass."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        real_commit = session.commit
        calls = {"n": 0}

        def _commit_that_loses_once():
            calls["n"] += 1
            if calls["n"] == 1:
                # The winner's row landing between our lookup and our insert.
                raise IntegrityError("duplicate", None, Exception("duplicate"))
            return real_commit()

        monkeypatch.setattr(session, "commit", _commit_that_loses_once)

        # Must not raise.
        created = core.ensure_workspace_default_rows(session)

        monkeypatch.undo()
        assert len(created) == len(list(ScanScheduleType)) - 1
        assert ws.id is not None


# ---------------------------------------------------------------------------
# Clock arithmetic: no per-cycle drift, no synchronised platform-wide burst
# ---------------------------------------------------------------------------


def test_advancing_anchors_to_the_previous_due_time(engine):
    """A tick that arrives four minutes late must not push the next run four
    minutes later and keep sliding; without an anchor a "daily" scan walks
    off its hour over a few weeks."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        due = utcnow() - timedelta(minutes=4)
        row = _schedule(session, ws, interval_hours=24, next_run_at=due)

        assert core.compute_next_run_at(session, row, utcnow()) == due + timedelta(hours=24)


def test_advancing_falls_back_to_a_fresh_interval_after_a_long_outage(engine):
    """Bounded rather than exact: the fallback re-jitters (see the next
    test), so pinning the un-jittered value here would be pinning the bug."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        row = _schedule(session, ws, interval_hours=1, next_run_at=utcnow() - timedelta(days=2))

        now = utcnow()
        nxt = core.compute_next_run_at(session, row, now)

        floor = now + timedelta(hours=1)
        assert floor <= nxt <= floor + core.MAX_JITTER


def test_the_outage_fallback_re_jitters(engine):
    """A long outage is the one moment when *every* row in the install falls
    back at once, in a single recovery pass sharing a single `now`. An
    un-jittered fallback would collapse the whole platform onto the same
    second -- and the anchor would then faithfully preserve that forever,
    undoing the seeded spread by exactly the route #229 cares most about."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        now = utcnow()
        rows = [
            _schedule(
                session, ws,
                scan_type=ScanScheduleType.FULL_SCAN if i == 0 else ScanScheduleType.API_SCAN,
                target=_make_target(session, ws, f"t{i}") if i > 1 else None,
                interval_hours=1,
                next_run_at=now - timedelta(days=2),
            )
            for i in range(6)
        ]

        nexts = {core.compute_next_run_at(session, row, now) for row in rows}

        # Not a strict guarantee of distinctness (random can repeat), but six
        # identical values would mean the fallback is not jittering.
        assert len(nexts) > 1


def test_seeded_defaults_are_jittered_forward_only(engine):
    """Without jitter every workspace seeded by the same tick shares one
    `now` and they all come due together forever after -- the whole
    platform's scheduled scans arriving as one burst. Forward-only, so a
    jittered schedule never fires earlier than its configured interval."""
    with Session(engine) as session:
        for i in range(6):
            _make_workspace(session, f"ws{i}")

        now = utcnow()
        created = core.ensure_workspace_default_rows(session, now=now)

        full_scan_rows = [r for r in created if r.scan_type == ScanScheduleType.FULL_SCAN]
        assert len(full_scan_rows) == 6
        floor = now + timedelta(hours=24)
        for row in full_scan_rows:
            assert floor <= row.next_run_at <= floor + core.MAX_JITTER
        # Not a strict guarantee of distinctness (random can repeat), but
        # six identical values would mean jitter is not being applied.
        assert len({r.next_run_at for r in full_scan_rows}) > 1


def test_the_next_due_time_is_always_strictly_after_now(engine):
    """compute_next_run_at's strictly-after-`now` invariant, on every branch.

    This is the promise claim_due_schedule's lock is built on: the winner
    writes back a value from this function, and every loser's
    `next_run_at <= now` predicate is then guaranteed false, so their
    rowcount is 0 and they skip. Weaken it and the UPDATE stops locking
    while still looking exactly like one -- the row stays claimable, the
    next pass re-claims it, and every target is scanned twice, with nothing
    failing anywhere to say so.

    Worth its own test because none of the claim tests above would catch it:
    they all use rows whose next due time lands comfortably clear of `now`,
    so the margin is never actually under pressure. These use the tightest
    configuration the validator permits (MIN_INTERVAL_HOURS) and sample the
    two jittered branches, so a change that makes the spread symmetric -- or
    otherwise lets it approach the interval -- fails here rather than in
    production as a silent double fan-out.
    """
    with Session(engine) as session:
        ws = _make_workspace(session)
        now = utcnow()
        interval = core.MIN_INTERVAL_HOURS

        # Branch 1: no stored clock at all -> the jittered fallback.
        never_set = _schedule(session, ws, interval_hours=interval, next_run_at=None)
        # Branch 2: the anchored answer lands exactly on `now`. The guard is
        # a strict `>`, so this must NOT be returned -- "equal to now" is not
        # still in the future, and returning it would be the one value that
        # defeats the lock by the narrowest possible margin.
        exactly_now = _schedule(
            session, ws, scan_type=ScanScheduleType.API_SCAN,
            interval_hours=interval, next_run_at=now - timedelta(hours=interval),
        )
        # Branch 3: the anchored answer is in the future, returned as-is.
        anchored = _schedule(
            session, ws, target=_make_target(session, ws, "t"),
            interval_hours=interval, next_run_at=now - timedelta(minutes=1),
        )

        for row in (never_set, exactly_now, anchored):
            # Sampled: two of the three branches go through random jitter, so
            # one draw proves very little.
            for _ in range(50):
                assert core.compute_next_run_at(session, row, now) > now

        # The boundary itself, stated separately from the loop so a failure
        # names it.
        assert core.compute_next_run_at(session, exactly_now, now) != now


# ---------------------------------------------------------------------------
# The API write path must not let a clock reset become a way to defer a scan
# ---------------------------------------------------------------------------


def test_a_no_op_save_does_not_push_the_next_run_out(engine):
    """A PUT that changes nothing (the panel re-saving the same values) used
    to reset the clock a full interval, so repeatedly saving kept a daily
    scan permanently deferred."""
    from app.api.scan_schedules import UpsertScanScheduleRequest, _apply

    with Session(engine) as session:
        ws = _make_workspace(session)
        due = utcnow() + timedelta(hours=3)
        row = _schedule(session, ws, enabled=True, interval_hours=24, next_run_at=due)

        _apply(
            session, row, workspace_id=ws.id, target_id=None,
            scan_type=ScanScheduleType.FULL_SCAN,
            payload=UpsertScanScheduleRequest(enabled=True, interval_hours=24),
            fields_set={"enabled", "interval_hours"},
        )
        session.refresh(row)

        assert row.next_run_at == due


def test_pausing_does_not_push_the_next_run_out(engine):
    """Resuming recomputes from now (a schedule that sat paused has a
    genuinely stale due time); the pause itself must not move it, or a
    pause-and-undo would silently cost a cycle."""
    from app.api.scan_schedules import UpsertScanScheduleRequest, _apply

    with Session(engine) as session:
        ws = _make_workspace(session)
        due = utcnow() + timedelta(hours=3)
        row = _schedule(session, ws, enabled=True, interval_hours=24, next_run_at=due)

        _apply(
            session, row, workspace_id=ws.id, target_id=None,
            scan_type=ScanScheduleType.FULL_SCAN,
            payload=UpsertScanScheduleRequest(enabled=False),
            fields_set={"enabled"},
        )
        session.refresh(row)

        assert row.next_run_at == due


def test_changing_the_interval_does_reset_the_clock(engine):
    """The stored due time was computed against a cadence that no longer
    applies; shortening an interval must not leave a mid-cycle schedule
    sitting overdue and fire the instant the dispatcher next ticks."""
    from app.api.scan_schedules import UpsertScanScheduleRequest, _apply

    with Session(engine) as session:
        ws = _make_workspace(session)
        due = utcnow() + timedelta(hours=20)
        row = _schedule(session, ws, enabled=True, interval_hours=24, next_run_at=due)

        _apply(
            session, row, workspace_id=ws.id, target_id=None,
            scan_type=ScanScheduleType.FULL_SCAN,
            payload=UpsertScanScheduleRequest(interval_hours=6),
            fields_set={"interval_hours"},
        )
        session.refresh(row)

        assert row.next_run_at < due
        assert row.next_run_at >= utcnow() + timedelta(hours=6) - timedelta(seconds=5)


# ---------------------------------------------------------------------------
# Target lifecycle: a schedule is not consent to scan something switched off
#
# #273 (target deactivate / soft-delete) lands on a parallel branch and adds
# the deactivated_at/deleted_at columns these read. is_dispatchable_target
# reads them defensively so this branch works standalone and gates for real
# the moment they exist; see its docstring.
# ---------------------------------------------------------------------------


class _LifecycleStub:
    """Stands in for a Target carrying #273's columns, which do not exist on
    this branch yet.

    This restates the column names by hand, so on its own it would keep
    passing even if #273 landed with different ones. What actually protects
    the names is the merge tripwire at the bottom of this file; these are
    only here to pin the predicate's logic.

    `name` is here because the predicate now routes through
    target_lifecycle.scan_refusal_reason, which names the target in the
    message it returns for a deactivated one."""

    def __init__(self, deactivated_at=None, deleted_at=None, name="stub-target"):
        self.deactivated_at = deactivated_at
        self.deleted_at = deleted_at
        self.name = name


def test_a_target_without_the_lifecycle_columns_is_dispatchable(engine):
    """Today's state: the columns are absent, so nothing is gated and
    behaviour is unchanged."""
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws)

        assert core.is_dispatchable_target(target) is True


def test_a_deactivated_target_is_not_dispatchable():
    assert core.is_dispatchable_target(_LifecycleStub(deactivated_at=utcnow())) is False


def test_a_soft_deleted_target_is_not_dispatchable():
    assert core.is_dispatchable_target(_LifecycleStub(deleted_at=utcnow())) is False


def test_the_dispatcher_skips_a_target_the_lifecycle_gate_rejects(engine, no_dispatch, monkeypatch):
    """The gate is wired into targets_covered_by, not merely defined.
    Without it a deactivated target would get a Scan row every single tick,
    which #273's worker-side gate then immediately fails -- forever."""
    full, _api = no_dispatch
    monkeypatch.setattr(core, "is_dispatchable_target", lambda t: t.name != "switched-off")

    with Session(engine) as session:
        ws = _make_workspace(session)
        _make_target(session, ws, "live")
        _make_target(session, ws, "switched-off")
        _schedule(session, ws, next_run_at=utcnow() - timedelta(minutes=1))

        schedule_tasks.dispatch_due_scan_schedules(session)

        assert [c.args[1].name for c in full.call_args_list] == ["live"]


def test_a_target_scoped_schedule_also_honours_the_lifecycle_gate(engine, no_dispatch, monkeypatch):
    full, _api = no_dispatch
    monkeypatch.setattr(core, "is_dispatchable_target", lambda t: False)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, "switched-off")
        row = _schedule(session, ws, target=target, next_run_at=utcnow() - timedelta(minutes=1))

        schedule_tasks.dispatch_due_scan_schedules(session)
        session.refresh(row)

        full.assert_not_called()
        assert row.last_dispatched_count == 0


# ---------------------------------------------------------------------------
# API-scan readiness: every refusal is reportable, not just api_base_url
#
# One function, read by both the dispatcher and the scheduling panel, so an
# armed schedule can never render as healthy while the worker skips it every
# cycle. Two of the three refusals used to be invisible in the UI.
# ---------------------------------------------------------------------------


def _discoverable(session, target):
    session.add(
        ApiEndpoint(
            target_id=target.id, branch="main", framework="fastapi",
            method="GET", route="/v1/users", file_path="app/main.py", line=1,
        )
    )
    session.commit()


def test_readiness_is_ready_for_a_fully_configured_target(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        _discoverable(session, target)

        readiness = core.describe_api_scan_readiness(session, target)

        assert readiness.ready is True
        assert readiness.reason is None


def test_readiness_reports_a_disabled_tool(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        _discoverable(session, target)
        session.add(WorkspaceToolConfig(workspace_id=ws.id, tool="nuclei", api_scan=False))
        session.commit()

        readiness = core.describe_api_scan_readiness(session, target)

        assert readiness.ready is False
        assert readiness.reason == "tool_disabled"
        assert readiness.detail


def test_readiness_reports_a_missing_api_base_url(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url=None)
        _discoverable(session, target)

        readiness = core.describe_api_scan_readiness(session, target)

        assert readiness.ready is False
        assert readiness.reason == "no_api_base_url"


def test_readiness_reports_no_discovered_endpoints(engine):
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")

        readiness = core.describe_api_scan_readiness(session, target)

        assert readiness.ready is False
        assert readiness.reason == "no_endpoints"


def test_readiness_reports_an_inactive_target(engine, monkeypatch):
    monkeypatch.setattr(core, "is_dispatchable_target", lambda t: False)
    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        _discoverable(session, target)

        readiness = core.describe_api_scan_readiness(session, target)

        assert readiness.ready is False
        assert readiness.reason == "target_inactive"


def test_queue_api_scan_refuses_on_the_same_readiness_answer(engine, monkeypatch):
    """The dispatcher and the panel must not be able to disagree: both read
    describe_api_scan_readiness, so a refusal is never invisible."""
    import app.tasks.api_scan_tasks as api_scan_tasks

    run = MagicMock()
    monkeypatch.setattr(api_scan_tasks.run_api_scan, "delay", run)
    monkeypatch.setattr(core, "is_dispatchable_target", lambda t: False)

    with Session(engine) as session:
        ws = _make_workspace(session)
        target = _make_target(session, ws, api_base_url="https://api.example.com")
        _discoverable(session, target)

        assert api_scan_tasks.queue_api_scan(session, target) is None
        run.assert_not_called()


def test_resuming_a_schedule_whose_due_time_has_passed_resets_the_clock(engine):
    """The case the reset exists for: a schedule that sat paused past its
    due time would otherwise fire the instant it is unpaused, across every
    target it covers."""
    from app.api.scan_schedules import UpsertScanScheduleRequest, _apply

    with Session(engine) as session:
        ws = _make_workspace(session)
        stale = utcnow() - timedelta(days=3)
        row = _schedule(session, ws, enabled=False, interval_hours=24, next_run_at=stale)

        _apply(
            session, row, workspace_id=ws.id, target_id=None,
            scan_type=ScanScheduleType.FULL_SCAN,
            payload=UpsertScanScheduleRequest(enabled=True),
            fields_set={"enabled"},
        )
        session.refresh(row)

        assert row.next_run_at > utcnow()


def test_resuming_before_the_due_time_keeps_it(engine):
    """The other half. "Do not fire the instant you unpause" only ever
    applied to a schedule whose moment had already gone by; a pause lifted an
    hour before a run was due has nothing stale about it, and resetting there
    costs a full cycle for no reason -- the same defect as resetting on a
    no-op, reached from the other side."""
    from app.api.scan_schedules import UpsertScanScheduleRequest, _apply

    with Session(engine) as session:
        ws = _make_workspace(session)
        due = utcnow() + timedelta(hours=1)
        row = _schedule(session, ws, enabled=False, interval_hours=24, next_run_at=due)

        _apply(
            session, row, workspace_id=ws.id, target_id=None,
            scan_type=ScanScheduleType.FULL_SCAN,
            payload=UpsertScanScheduleRequest(enabled=True),
            fields_set={"enabled"},
        )
        session.refresh(row)

        assert row.next_run_at == due


# ---------------------------------------------------------------------------
# Merge tripwire for the lifecycle gate
#
# is_dispatchable_target reads #273's columns through getattr so this branch
# imports standalone (see its docstring). The risk that buys is silence: the
# stub above and the monkeypatched wiring tests both restate the column names
# by hand, so if #273 landed with different names, every test here would stay
# green while the gate failed open.
#
# That matters asymmetrically. #273 puts its own refusal in queue_full_scan,
# so the full-scan path is belt-and-braces either way -- but queue_api_scan
# does not exist on that branch, which makes this getattr the only thing
# stopping a schedule from firing nuclei at a deactivated target. Probing a
# live host somebody switched off is the failure mode that must not be able
# to regress quietly.
#
# So: skipped while app.core.target_lifecycle does not exist, red the moment
# it does and this is still a getattr. That is exactly when the docstring's
# "collapses to a direct call" is supposed to happen, and the same commit
# that satisfies this test is the one that proves the names still match.
# ---------------------------------------------------------------------------


def test_lifecycle_gate_is_collapsed_once_273_has_landed():
    try:
        import app.core.target_lifecycle  # noqa: F401
    except ModuleNotFoundError:
        # Deliberately NOT `except ImportError`. ModuleNotFoundError
        # subclasses it, so the broad catch would also swallow the case
        # where target_lifecycle exists but raises ImportError from its own
        # imports -- and this tripwire would then skip after #445 merged,
        # which is precisely the silence it exists to prevent. Anything
        # other than "the module is not there" propagates as a real failure.
        pytest.skip(
            "app.core.target_lifecycle does not exist yet (#273/#445 unmerged); "
            "is_dispatchable_target's defensive getattr is still correct here"
        )

    from app.models.models import Target as TargetModel

    missing = [
        name for name in ("deactivated_at", "deleted_at") if not hasattr(TargetModel, name)
    ]
    assert not missing, (
        f"is_dispatchable_target reads {missing} off Target, but #273 landed without "
        f"them -- the gate is failing open and scheduled scans are reaching targets "
        f"somebody switched off. Update it to whatever the real predicate is."
    )

    # Parsed, not substring-matched. The first version of this checked
    # `"getattr" not in source`, which fails against a docstring that merely
    # *explains* the collapse -- so the tripwire went red on the very commit
    # that satisfied it. What it means to assert is "no getattr is called
    # here", and that is a property of the code, not of the text.
    tree = ast.parse(textwrap.dedent(inspect.getsource(core.is_dispatchable_target)))
    calls_getattr = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        for node in ast.walk(tree)
    )
    assert not calls_getattr, (
        "app.core.target_lifecycle now exists, so is_dispatchable_target should call it "
        "directly instead of reading Target's lifecycle columns through getattr. The "
        "getattr was only there so this branch could import before #273 merged; leaving "
        "it in means a later rename silently stops gating instead of failing here."
    )
