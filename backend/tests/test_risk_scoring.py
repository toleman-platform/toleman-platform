"""Configurable risk prioritisation (#201 phases 1-2).

Four properties this suite exists to hold, in descending order of how bad it
is to lose one:

1. **An unknown signal never lowers a score.** #201's hard rule, and the
   same one #246/#243/#253 keep restating: "we did not establish X" is never
   "X is absent". A violation here is a security regression -- findings
   quietly sorted down the list because enrichment had not run yet -- not a
   style problem.
2. **The shipped baseline reproduces today's scores exactly.** An install
   that configures nothing must not see its backlog re-ranked, its SLA
   breaches move, or PR Guardrail's blocking set change on upgrade.
3. **Every weight actually moves the score.** A configuration surface whose
   dials do nothing is worse than no configuration surface, because someone
   will set one and believe it.
4. **The explanation accounts for every signal**, including the ones that
   contributed nothing, and adds up to the number it claims to explain.

Same in-memory SQLite + TestClient pattern as tests/test_sla_rules.py and
tests/test_fixability.py.
"""

import itertools

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.cve_enrichment import apply_cvss_decomposition
from app.core.cvss import UNKNOWN_CVSS, parse_cvss_vector
from app.core.fixability import FIXABLE, NO_KNOWN_FIX, UNKNOWN
from app.core.scoring import (
    BASELINE_WEIGHTS,
    EPSS_BUMP,
    INTERNET_EXPOSURE_MAX_POINTS,
    KEV_FLOOR,
    MAX_SCORE,
    MAX_WEIGHT,
    PRODUCTION_EXPOSURE_FACTOR,
    compute_priority_score,
    compute_score_breakdown,
    resolve_exposure,
    resolve_weights,
)
from app.core.scoring_config import (
    cvss_for_enrichment,
    score_breakdown_for_finding,
    signal_catalog,
    workspace_scoring_weights,
)
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    CveEnrichment,
    Finding,
    Organization,
    ScoringSignal,
    ScoringWeight,
    Severity,
    SEVERITY_WEIGHT,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)

V31_WORST = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
ALL_SEVERITIES = list(Severity)


# --------------------------------------------------------------------------
# Property 2: the shipped baseline is today's formula, exactly.
# --------------------------------------------------------------------------


def legacy_priority_score(severity, criticality, epss_score=None, kev_listed=False) -> int:
    """The pre-#201 implementation, copied verbatim from git history.

    Deliberately a duplicate rather than an import: the point is to pin the
    *old* behaviour independently of whatever the current module does, so a
    change to scoring.py that alters the baseline fails here instead of
    updating its own reference.
    """
    weight = SEVERITY_WEIGHT[severity]
    base = weight * max(1, min(5, criticality)) * 40
    score = min(1000, base)
    if kev_listed:
        score = max(score, 900)
    elif epss_score is not None and epss_score > 0.5:
        score = min(1000, score + 160)
    return score


@pytest.mark.parametrize(
    "severity,criticality,epss,kev",
    list(
        itertools.product(
            ALL_SEVERITIES,
            [0, 1, 2, 3, 4, 5, 99],
            [None, 0.0, 0.1, 0.5, 0.51, 0.9, 1.0],
            [False, True],
        )
    ),
)
def test_baseline_reproduces_the_pre_201_score_exactly(severity, criticality, epss, kev):
    """The whole matrix, not a spot check. 490 combinations is cheap, and a
    scoring regression that only shows up at one severity tier on one
    criticality weight is exactly the kind that ships."""
    assert compute_priority_score(severity, criticality, epss_score=epss, kev_listed=kev) == (
        legacy_priority_score(severity, criticality, epss_score=epss, kev_listed=kev)
    )


def test_baseline_is_unchanged_even_when_every_new_signal_is_present():
    """The strong form of property 2: a finding that lights up all three
    *new* signals -- a public production target, a worst-case CVSS vector,
    an available fix -- still scores exactly what it scored before #201,
    because those signals ship at weight 0.

    This is why BASELINE_WEIGHTS does not give the new signals a
    sensible-looking default. Re-ranking every install's backlog on upgrade
    is an incident, not a feature.
    """
    scored = compute_priority_score(
        Severity.HIGH,
        3,
        epss_score=0.9,
        kev_listed=False,
        cvss=parse_cvss_vector(V31_WORST),
        target_label="Public",
        target_environment="production",
        fixability=FIXABLE,
    )
    assert scored == legacy_priority_score(Severity.HIGH, 3, epss_score=0.9)


def test_baseline_weights_are_the_defaults_for_an_unconfigured_workspace(engine):
    ws_id = _make_workspace(engine)
    with Session(engine) as session:
        assert workspace_scoring_weights(session, ws_id) == BASELINE_WEIGHTS


def test_new_signals_ship_switched_off():
    for signal in (
        ScoringSignal.CVSS_EXPLOITABILITY,
        ScoringSignal.INTERNET_EXPOSURE,
        ScoringSignal.FIXABILITY,
    ):
        assert BASELINE_WEIGHTS[signal] == 0.0
    for signal in (
        ScoringSignal.SEVERITY,
        ScoringSignal.BUSINESS_CRITICALITY,
        ScoringSignal.EPSS,
        ScoringSignal.KEV,
    ):
        assert BASELINE_WEIGHTS[signal] == 1.0


def test_reachability_is_not_a_shipped_signal_slot():
    """Phase 3 of #201 depends on #183, an unresolved spike. An inert
    `reachability` slot would advertise a signal nothing computes, and
    someone would weight it and believe their scores accounted for it."""
    assert not any("reach" in s.value for s in ScoringSignal)
    assert not any("reach" in entry["signal"] for entry in signal_catalog())


# --------------------------------------------------------------------------
# Property 3: every weight moves the score.
# --------------------------------------------------------------------------


def _weights(**overrides) -> dict:
    return {ScoringSignal(k): v for k, v in overrides.items()}


def test_severity_weight_moves_the_score():
    low = compute_priority_score(Severity.CRITICAL, 2, weights=_weights(severity=0.0))
    high = compute_priority_score(Severity.CRITICAL, 2, weights=_weights(severity=1.0))
    assert low < high
    # At weight 0 severity stops influencing the score at all, so a Critical
    # and an Informational finding on the same target tie.
    assert low == compute_priority_score(Severity.INFO, 2, weights=_weights(severity=0.0))


def test_business_criticality_weight_moves_the_score():
    off = compute_priority_score(Severity.HIGH, 5, weights=_weights(business_criticality=0.0))
    on = compute_priority_score(Severity.HIGH, 5, weights=_weights(business_criticality=1.0))
    assert off < on
    assert off == compute_priority_score(Severity.HIGH, 1, weights=_weights(business_criticality=0.0))


def test_kev_weight_moves_the_floor():
    full = compute_priority_score(Severity.LOW, 1, kev_listed=True, weights=_weights(kev=1.0))
    half = compute_priority_score(Severity.LOW, 1, kev_listed=True, weights=_weights(kev=0.5))
    off = compute_priority_score(Severity.LOW, 1, kev_listed=True, weights=_weights(kev=0.0))
    assert full == KEV_FLOOR
    assert half == round(KEV_FLOOR * 0.5)
    # Weight 0 removes the floor entirely; the score falls back to the base
    # formula rather than to zero.
    assert off == compute_priority_score(Severity.LOW, 1)


def test_epss_weight_moves_the_bump():
    base = compute_priority_score(Severity.MEDIUM, 3)
    doubled = compute_priority_score(Severity.MEDIUM, 3, epss_score=0.9, weights=_weights(epss=2.0))
    assert doubled == base + 2 * EPSS_BUMP


def test_cvss_exploitability_weight_moves_the_score():
    worst = parse_cvss_vector(V31_WORST)
    off = compute_priority_score(Severity.MEDIUM, 2, cvss=worst)
    on = compute_priority_score(Severity.MEDIUM, 2, cvss=worst, weights=_weights(cvss_exploitability=1.0))
    assert off < on


def test_internet_exposure_weight_moves_the_score():
    off = compute_priority_score(Severity.MEDIUM, 2, target_label="Public")
    on = compute_priority_score(
        Severity.MEDIUM, 2, target_label="Public", weights=_weights(internet_exposure=1.0)
    )
    assert off < on


def test_fixability_weight_moves_the_score():
    off = compute_priority_score(Severity.MEDIUM, 2, fixability=FIXABLE)
    on = compute_priority_score(Severity.MEDIUM, 2, fixability=FIXABLE, weights=_weights(fixability=1.0))
    assert off < on


def test_every_signal_slot_has_a_weight_that_moves_a_score():
    """Belt and braces over the individual cases above: iterate the catalogue
    so a signal added later cannot ship as a dial that does nothing."""
    for signal in ScoringSignal:
        # Everything at zero except the signal under test, compared against
        # everything at zero, so the difference is attributable to that one
        # dial. The base formula floors at 40 rather than 0, which keeps the
        # totals far enough below the 1000 cap for it not to mask an effect.
        #
        # kev_listed tracks the signal under test on purpose: KEV
        # deliberately supersedes EPSS (observed exploitation outranks a
        # prediction), so leaving KEV on for every case would make the EPSS
        # dial look inert when it is in fact correctly deferring.
        kwargs = dict(
            epss_score=0.9,
            kev_listed=(signal == ScoringSignal.KEV),
            cvss=parse_cvss_vector(V31_WORST),
            target_label="Public",
            target_environment="production",
            fixability=FIXABLE,
        )
        zeroed = {s: 0.0 for s in ScoringSignal}
        baseline = compute_priority_score(Severity.MEDIUM, 3, weights=zeroed, **kwargs)
        lifted = compute_priority_score(Severity.MEDIUM, 3, weights={**zeroed, signal: 1.0}, **kwargs)
        assert lifted > baseline, f"weight for {signal.value} does not move the score"


def test_negative_weights_are_clamped_so_no_signal_can_subtract():
    """The structural guarantee behind property 1: if no signal can ever
    subtract, an unknown signal cannot lower a score either."""
    clamped = resolve_weights({ScoringSignal.EPSS: -5.0})
    assert clamped[ScoringSignal.EPSS] == 0.0
    assert compute_priority_score(
        Severity.MEDIUM, 3, epss_score=0.9, weights={ScoringSignal.EPSS: -5.0}
    ) == compute_priority_score(Severity.MEDIUM, 3)


def test_unparseable_weight_falls_back_to_the_baseline():
    assert resolve_weights({ScoringSignal.EPSS: "banana"})[ScoringSignal.EPSS] == 1.0


@pytest.mark.parametrize("bad", [float("inf"), float("-inf"), float("nan")])
def test_non_finite_weights_fall_back_to_the_baseline_rather_than_raising(bad):
    """Postgres float8 stores 'Infinity' and 'NaN' happily, and this table is
    writable by anything holding a connection. An infinite weight is not an
    absurdly high priority -- `round(inf)` raises OverflowError, which would
    500 every scoring call, findings list and scan in the workspace. The
    baseline stands in rather than MAX_WEIGHT: silently promoting a corrupt
    row to the strongest setting is worse than ignoring it."""
    assert resolve_weights({ScoringSignal.EPSS: bad})[ScoringSignal.EPSS] == 1.0
    # The real regression: this must not raise.
    score = compute_priority_score(
        Severity.MEDIUM, 3, target_label="Public", weights={ScoringSignal.INTERNET_EXPOSURE: bad}
    )
    assert score == compute_priority_score(Severity.MEDIUM, 3, target_label="Public")


def test_absurdly_high_weights_are_clamped_by_the_engine_too():
    """The API rejects out-of-range weights, but it is not the only writer;
    a script or a psql session bypasses it entirely."""
    assert resolve_weights({ScoringSignal.EPSS: 10_000.0})[ScoringSignal.EPSS] == MAX_WEIGHT


# --------------------------------------------------------------------------
# Property 1: unknown never lowers a score.
# --------------------------------------------------------------------------

ALL_ON = {s: 1.0 for s in ScoringSignal}


def test_unknown_cvss_vector_never_lowers_a_score():
    known_benign = compute_score_breakdown(
        Severity.HIGH, 3, cvss=parse_cvss_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R"), weights=ALL_ON
    ).score
    unknown = compute_score_breakdown(Severity.HIGH, 3, cvss=UNKNOWN_CVSS, weights=ALL_ON).score
    absent = compute_score_breakdown(Severity.HIGH, 3, cvss=None, weights=ALL_ON).score
    no_signal = compute_score_breakdown(Severity.HIGH, 3, weights=ALL_ON).score

    assert unknown == absent == no_signal
    # And specifically: not knowing must not score below the least
    # exploitable thing we could have known.
    assert unknown >= no_signal
    assert known_benign >= unknown  # a decoded vector can only ever add


def test_unknown_fixability_never_lowers_a_score():
    unknown = compute_priority_score(Severity.HIGH, 3, fixability=UNKNOWN, weights=ALL_ON)
    absent = compute_priority_score(Severity.HIGH, 3, fixability=None, weights=ALL_ON)
    no_fix = compute_priority_score(Severity.HIGH, 3, fixability=NO_KNOWN_FIX, weights=ALL_ON)
    fixable = compute_priority_score(Severity.HIGH, 3, fixability=FIXABLE, weights=ALL_ON)
    assert unknown == absent == no_fix
    assert fixable > unknown


def test_unrecorded_exposure_never_lowers_a_score():
    nothing_recorded = compute_priority_score(Severity.HIGH, 3, weights=ALL_ON)
    internal = compute_priority_score(Severity.HIGH, 3, target_label="Internal", weights=ALL_ON)
    unrecognised = compute_priority_score(Severity.HIGH, 3, target_label="Banana", weights=ALL_ON)
    public = compute_priority_score(Severity.HIGH, 3, target_label="Public", weights=ALL_ON)

    assert internal == nothing_recorded
    # An environment vocabulary we don't recognise is unknown, not private,
    # and must not be scored below a target with nothing recorded at all.
    assert unrecognised >= nothing_recorded
    assert public > nothing_recorded


def test_missing_epss_never_lowers_a_score():
    absent = compute_priority_score(Severity.HIGH, 3, epss_score=None, weights=ALL_ON)
    low = compute_priority_score(Severity.HIGH, 3, epss_score=0.01, weights=ALL_ON)
    assert absent == low


def test_adding_any_single_signal_can_only_raise_a_score():
    """One signal at a time, against a finding with none of them: adding a
    piece of information must never produce a lower number.

    Note what this does and does not claim. It pins the property the
    failsafe rule needs -- knowing something is never worse than knowing
    nothing -- across every signal. It is NOT exhaustive over combinations,
    and the CVSS sub-score is deliberately not monotonic in how *much* of a
    vector was decoded -- see test_partial_vector_is_never_worse_than_no_vector
    and test_the_mean_is_not_monotonic_in_how_much_was_decoded in
    tests/test_cvss.py, plus the note in app/core/cvss.py."""
    base = compute_score_breakdown(Severity.MEDIUM, 2, weights=ALL_ON).score
    for extra in (
        dict(cvss=parse_cvss_vector(V31_WORST)),
        dict(cvss=parse_cvss_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R")),
        dict(epss_score=0.02),
        dict(epss_score=0.99),
        dict(kev_listed=True),
        dict(target_label="Public"),
        dict(target_label="Internal"),
        dict(target_environment="production"),
        dict(target_environment="dev"),
        dict(fixability=FIXABLE),
        dict(fixability=NO_KNOWN_FIX),
        dict(fixability=UNKNOWN),
    ):
        assert compute_score_breakdown(Severity.MEDIUM, 2, weights=ALL_ON, **extra).score >= base, extra


def test_no_contribution_is_ever_negative():
    breakdown = compute_score_breakdown(
        Severity.INFO,
        1,
        epss_score=0.01,
        kev_listed=False,
        cvss=parse_cvss_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R"),
        target_label="Internal",
        target_environment="dev",
        fixability=NO_KNOWN_FIX,
        weights=ALL_ON,
    )
    assert all(c.points >= 0 for c in breakdown.contributions)


# --------------------------------------------------------------------------
# Exposure resolution (#201 phase 2).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("label", ["Public", "public", "External", "internet-facing", "DMZ"])
def test_public_labels_are_recognised_as_internet_facing(label):
    exposure = resolve_exposure(label, None)
    assert exposure.factor == 1.0
    assert exposure.established


def test_production_is_a_weaker_claim_than_public():
    """Plenty of production services sit entirely behind a VPN. "Runs in
    prod" earns a partial uplift, not the full one."""
    prod = resolve_exposure(None, "production")
    public = resolve_exposure("Public", None)
    assert 0 < prod.factor < public.factor
    assert prod.established


def test_internal_is_established_but_earns_nothing():
    exposure = resolve_exposure("Internal", "staging")
    assert exposure.factor == 0.0
    assert exposure.established  # we know; it just adds nothing


def test_explicit_private_label_beats_a_production_environment():
    """Regression: the production branch used to run before the private-label
    branch, so ("Internal", "production") picked up the production uplift and
    the explanation never mentioned the label contradicting it. A production
    service behind a VPN is an ordinary thing; the label is the statement
    about network posture, the environment is a deployment stage."""
    exposure = resolve_exposure("Internal", "production")
    assert exposure.factor == 0.0
    assert exposure.established
    # And it has to *say* the label is why, or someone looking at a
    # production service scoring no exposure cannot tell what to fix.
    assert "Internal" in exposure.detail
    assert "production" in exposure.detail


def test_public_label_still_beats_a_non_production_environment():
    """The same precedence, in the other direction."""
    assert resolve_exposure("Public", "dev").factor == 1.0


def test_production_uplift_still_applies_with_no_label_conflict():
    for label in (None, "", "tier-1"):
        assert resolve_exposure(label, "production").factor == PRODUCTION_EXPOSURE_FACTOR


def test_production_detail_names_the_field_that_actually_matched():
    """Regression: `raw_env or raw_label` picked the environment even when
    the *label* was what matched, so label="prod", environment="staging"
    rendered 'target runs in "staging"; production' -- a sentence
    contradicting itself, in the panel whose whole job is being true."""
    by_label = resolve_exposure("prod", "staging")
    assert by_label.factor == PRODUCTION_EXPOSURE_FACTOR
    assert 'runs in "staging"; production' not in by_label.detail
    # Names the label that decided it, and the environment it overrode.
    assert '"prod"' in by_label.detail and '"staging"' in by_label.detail

    by_env = resolve_exposure("tier-1", "production")
    assert 'runs in "production"' in by_env.detail
    assert "tier-1" not in by_env.detail  # did not decide anything

    both = resolve_exposure("prod", "live")
    assert '"prod"' in both.detail and '"live"' in both.detail

    # The production branch's fourth sub-case: the label decided, and there
    # is no environment worth mentioning -- either absent, or recorded in a
    # vocabulary we do not recognise. Naming it either way would imply it
    # was weighed, and an unrecognised value was explicitly *not* weighed
    # (it is unknown, not non-production).
    for env in (None, "", "   ", "eu-west-live-a"):
        label_only = resolve_exposure("prod", env)
        assert label_only.factor == PRODUCTION_EXPOSURE_FACTOR
        assert label_only.established
        assert label_only.detail.startswith('target is labelled "prod";')
        assert "wins over" not in label_only.detail
        assert "runs in" not in label_only.detail
        if env and env.strip():
            assert env not in label_only.detail


def test_nothing_recorded_is_unknown_not_internal():
    exposure = resolve_exposure(None, None)
    assert exposure.factor == 0.0
    assert not exposure.established
    assert "no label or environment" in exposure.detail


def test_unrecognised_vocabulary_is_unknown_not_internal():
    """Target.label/environment are free text by #251's design, so an
    org's own word for an environment must read as unknown rather than be
    assumed private."""
    exposure = resolve_exposure("tier-1-edge-fleet", "eu-west-live-a")
    assert not exposure.established
    assert exposure.factor == 0.0


def test_label_wins_over_environment():
    """`label="Public"` is someone explicitly saying "this faces the
    internet"; environment only correlates with it."""
    assert resolve_exposure("Public", "dev").factor == 1.0


# --------------------------------------------------------------------------
# Property 4: the explanation accounts for everything.
# --------------------------------------------------------------------------


def test_breakdown_lists_every_signal_slot_including_the_silent_ones():
    breakdown = compute_score_breakdown(Severity.LOW, 1)
    listed = {c.signal for c in breakdown.contributions}
    assert listed == set(ScoringSignal)


def test_breakdown_parts_add_up_to_the_score():
    for weights in (BASELINE_WEIGHTS, ALL_ON):
        breakdown = compute_score_breakdown(
            Severity.HIGH,
            4,
            epss_score=0.7,
            cvss=parse_cvss_vector(V31_WORST),
            target_label="Public",
            fixability=FIXABLE,
            weights=weights,
        )
        total = breakdown.base_points + sum(c.points for c in breakdown.contributions)
        if breakdown.capped:
            assert breakdown.score == MAX_SCORE
            assert total >= breakdown.score
        else:
            assert total == breakdown.score


def test_breakdown_distinguishes_established_zero_from_unknown_zero():
    """`points == 0` means two unrelated things and the API has to keep them
    apart: "EPSS is 3%, below the threshold" is a statement about the
    finding; "no EPSS score resolved" is an absence of data."""
    low_epss = compute_score_breakdown(Severity.HIGH, 3, epss_score=0.03)
    contribution = low_epss.contribution(ScoringSignal.EPSS)
    assert contribution.points == 0 and contribution.established

    no_epss = compute_score_breakdown(Severity.HIGH, 3, epss_score=None)
    contribution = no_epss.contribution(ScoringSignal.EPSS)
    assert contribution.points == 0 and not contribution.established


def test_unknown_cve_signals_say_which_kind_of_unknown_they_are():
    """"This finding has no CVE" and "this CVE has not been enriched yet" are
    different facts: the first signal can never fire for that finding, the
    second just has not fired yet. Someone deciding whether to weight the
    signal at all cannot tell those apart from one shared sentence."""
    no_cve = compute_score_breakdown(Severity.HIGH, 3, cve_id=None, weights=ALL_ON)
    assert "no CVE" in no_cve.contribution(ScoringSignal.CVSS_EXPLOITABILITY).detail
    assert "no CVE" in no_cve.contribution(ScoringSignal.FIXABILITY).detail

    unenriched = compute_score_breakdown(Severity.HIGH, 3, cve_id="CVE-2024-1234", weights=ALL_ON)
    cvss_detail = unenriched.contribution(ScoringSignal.CVSS_EXPLOITABILITY).detail
    assert "CVE-2024-1234" in cvss_detail and "not run" in cvss_detail
    assert "CVE-2024-1234" in unenriched.contribution(ScoringSignal.FIXABILITY).detail

    # Both still unestablished, and both still worth zero points.
    for breakdown in (no_cve, unenriched):
        for signal in (ScoringSignal.CVSS_EXPLOITABILITY, ScoringSignal.FIXABILITY):
            assert not breakdown.contribution(signal).established
            assert breakdown.contribution(signal).points == 0


def test_a_v2_vector_explains_why_it_scores_nothing():
    """A decoded-but-unscoreable vector must not read the same as an absent
    one, or the v2 carve-out looks like a parsing failure."""
    contribution = compute_score_breakdown(
        Severity.HIGH, 3, cvss=parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P"), weights=ALL_ON
    ).contribution(ScoringSignal.CVSS_EXPLOITABILITY)
    assert contribution.points == 0
    assert not contribution.established
    assert "v2" in contribution.detail
    assert "Attack Vector: network" in contribution.detail  # what we did decode


def test_kev_absence_is_not_claimed_as_a_verified_negative():
    """fetch_kev_cve_set() returns an empty set when CISA is unreachable, so
    kev_listed=False is the absence of a hit, not proof of anything."""
    contribution = compute_score_breakdown(Severity.HIGH, 3, kev_listed=False).contribution(
        ScoringSignal.KEV
    )
    assert not contribution.established


def test_breakdown_explains_the_decomposed_cvss_metrics():
    contribution = compute_score_breakdown(
        Severity.HIGH, 3, cvss=parse_cvss_vector(V31_WORST), weights=ALL_ON
    ).contribution(ScoringSignal.CVSS_EXPLOITABILITY)
    assert contribution.established
    assert "Attack Vector: network" in contribution.detail
    assert "Privileges Required: none" in contribution.detail
    assert contribution.points > 0


def test_breakdown_names_the_target_metadata_behind_criticality():
    """#251's point: a criticality weight nobody can audit is an assertion."""
    contribution = compute_score_breakdown(
        Severity.HIGH, 5, target_owner="platform-team", target_environment="production"
    ).contribution(ScoringSignal.BUSINESS_CRITICALITY)
    assert "platform-team" in contribution.detail
    assert "production" in contribution.detail


def test_epss_says_when_it_was_superseded_by_kev_rather_than_going_silent():
    contribution = compute_score_breakdown(
        Severity.LOW, 1, epss_score=0.99, kev_listed=True
    ).contribution(ScoringSignal.EPSS)
    assert contribution.points == 0
    assert "KEV" in contribution.detail


def test_score_is_capped_and_says_so():
    breakdown = compute_score_breakdown(
        Severity.CRITICAL,
        5,
        epss_score=0.99,
        cvss=parse_cvss_vector(V31_WORST),
        target_label="Public",
        fixability=FIXABLE,
        weights=ALL_ON,
    )
    assert breakdown.score == MAX_SCORE
    assert breakdown.capped


def test_capped_signal_reports_the_points_it_actually_contributed():
    breakdown = compute_score_breakdown(
        Severity.CRITICAL, 5, cvss=parse_cvss_vector(V31_WORST), weights=ALL_ON
    )
    cvss = breakdown.contribution(ScoringSignal.CVSS_EXPLOITABILITY)
    # The base formula already reaches 1000, so there is nothing left to
    # add, and the breakdown must not claim points it did not contribute.
    assert cvss.points == 0
    assert breakdown.score == MAX_SCORE


# --------------------------------------------------------------------------
# Database + API
# --------------------------------------------------------------------------


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = override_get_session
    original_engine = deps_module.engine
    deps_module.engine = engine
    c = TestClient(fastapi_app)
    yield c
    fastapi_app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _login(client, engine, role=UserRole.ADMIN, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _make_workspace(engine, name="ws") -> int:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}-{id(object())}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}-{id(object())}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


def _make_target(engine, workspace_id, **kwargs) -> int:
    with Session(engine) as session:
        t = Target(
            workspace_id=workspace_id,
            name="repo",
            repo_url="https://github.com/acme/repo",
            **kwargs,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


def _make_finding(engine, target_id, **kwargs) -> int:
    with Session(engine) as session:
        f = Finding(
            target_id=target_id,
            dedup_hash=f"hash-{id(object())}",
            tool="trivy",
            rule_id="CVE-2024-0001",
            title="vulnerable dep",
            file_path="requirements.txt",
            severity=kwargs.pop("severity", Severity.HIGH),
            **kwargs,
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f.id


def _grant(engine, user_id, workspace_id, role):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


def test_get_scoring_weights_returns_the_whole_catalogue_at_baseline(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)

    response = client.get(f"/api/scoring-weights?workspace_id={ws_id}")
    assert response.status_code == 200
    body = response.json()
    assert {s["signal"] for s in body["signals"]} == {s.value for s in ScoringSignal}
    assert all(s["is_default"] and s["rule_id"] is None for s in body["signals"])
    assert all(s["weight"] == s["baseline_weight"] for s in body["signals"])


def test_setting_a_weight_persists_and_marks_it_non_default(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)

    response = client.put(
        "/api/scoring-weights",
        json={"workspace_id": ws_id, "signal": "internet_exposure", "weight": 1.5},
    )
    assert response.status_code == 200
    entry = next(s for s in response.json()["signals"] if s["signal"] == "internet_exposure")
    assert entry["weight"] == 1.5
    assert not entry["is_default"]
    assert entry["rule_id"] is not None

    with Session(engine) as session:
        rows = session.exec(select(ScoringWeight).where(ScoringWeight.workspace_id == ws_id)).all()
        assert len(rows) == 1


def test_setting_the_same_weight_twice_updates_rather_than_duplicates(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    body = {"workspace_id": ws_id, "signal": "epss", "weight": 2.0}
    client.put("/api/scoring-weights", json=body)
    client.put("/api/scoring-weights", json={**body, "weight": 0.5})

    with Session(engine) as session:
        rows = session.exec(select(ScoringWeight).where(ScoringWeight.workspace_id == ws_id)).all()
        assert len(rows) == 1
        assert rows[0].weight == 0.5


def test_deleting_a_weight_reverts_to_the_shipped_baseline(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    created = client.put(
        "/api/scoring-weights", json={"workspace_id": ws_id, "signal": "kev", "weight": 0.0}
    ).json()
    rule_id = next(s for s in created["signals"] if s["signal"] == "kev")["rule_id"]

    response = client.delete(f"/api/scoring-weights/{rule_id}")
    assert response.status_code == 200
    entry = next(s for s in response.json()["signals"] if s["signal"] == "kev")
    assert entry["is_default"]
    assert entry["weight"] == BASELINE_WEIGHTS[ScoringSignal.KEV]


def test_negative_weights_are_rejected_rather_than_clamped_at_the_api(client, engine):
    """Clamping would silently do something other than what was asked. A
    caller asking for a signal that subtracts should be told no."""
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    response = client.put(
        "/api/scoring-weights", json={"workspace_id": ws_id, "signal": "epss", "weight": -1.0}
    )
    assert response.status_code == 422


def test_absurd_weights_are_rejected(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    response = client.put(
        "/api/scoring-weights", json={"workspace_id": ws_id, "signal": "epss", "weight": 500}
    )
    assert response.status_code == 422


def test_unknown_signal_slot_is_rejected(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    response = client.put(
        "/api/scoring-weights",
        json={"workspace_id": ws_id, "signal": "reachability", "weight": 1.0},
    )
    assert response.status_code == 422


def test_non_member_cannot_read_another_workspaces_configuration(client, engine):
    ws_id = _make_workspace(engine)
    client, _ = _login(client, engine, role=UserRole.USER)
    assert client.get(f"/api/scoring-weights?workspace_id={ws_id}").status_code == 404


def test_developer_cannot_change_weights(client, engine):
    """Turning severity down re-ranks the whole workspace and moves what PR
    Guardrail blocks; that is security policy, gated like SLA rules."""
    ws_id = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.USER)
    _grant(engine, uid, ws_id, WorkspaceRole.DEVELOPER)
    response = client.put(
        "/api/scoring-weights", json={"workspace_id": ws_id, "signal": "severity", "weight": 0.0}
    )
    assert response.status_code == 403


def test_security_engineer_can_change_weights(client, engine):
    ws_id = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.USER)
    _grant(engine, uid, ws_id, WorkspaceRole.SECURITY_ENGINEER)
    response = client.put(
        "/api/scoring-weights", json={"workspace_id": ws_id, "signal": "severity", "weight": 0.5}
    )
    assert response.status_code == 200


# --- the breakdown endpoint ---


def test_score_breakdown_endpoint_explains_every_signal(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, label="Public", environment="production", criticality_weight=4)
    finding_id = _make_finding(engine, target_id, severity=Severity.HIGH, priority_score=640)

    response = client.get(f"/api/findings/{finding_id}/score-breakdown")
    assert response.status_code == 200
    body = response.json()
    assert {s["signal"] for s in body["signals"]} == {s.value for s in ScoringSignal}
    assert body["stored_score"] == 640
    assert all(s["detail"] for s in body["signals"])


def test_score_breakdown_reports_stored_and_live_scores_separately(client, engine):
    """A weight change (or enrichment arriving after ingestion) legitimately
    moves the live score away from the stored one. The endpoint says so
    rather than quietly picking whichever number it prefers."""
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, label="Public", criticality_weight=2)
    finding_id = _make_finding(engine, target_id, severity=Severity.MEDIUM, priority_score=240)

    assert client.get(f"/api/findings/{finding_id}/score-breakdown").json()["stale"] is False

    client.put(
        "/api/scoring-weights",
        json={"workspace_id": ws_id, "signal": "internet_exposure", "weight": 1.0},
    )
    body = client.get(f"/api/findings/{finding_id}/score-breakdown").json()
    assert body["stored_score"] == 240
    assert body["score"] > 240
    assert body["stale"] is True


def test_score_breakdown_for_a_finding_with_no_cve_reports_unknown_not_benign(client, engine):
    client, _ = _login(client, engine)
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id, cve_id=None)

    body = client.get(f"/api/findings/{finding_id}/score-breakdown").json()
    by_signal = {s["signal"]: s for s in body["signals"]}
    for signal in ("cvss_exploitability", "fixability"):
        assert by_signal[signal]["established"] is False
        assert by_signal[signal]["points"] == 0


def test_score_breakdown_404s_for_a_finding_in_an_invisible_workspace(client, engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    finding_id = _make_finding(engine, target_id)
    client, _ = _login(client, engine, role=UserRole.USER)
    assert client.get(f"/api/findings/{finding_id}/score-breakdown").status_code == 404


# --- signals resolved from the database ---


def test_score_breakdown_for_finding_uses_the_persisted_cvss_decomposition(engine):
    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, criticality_weight=2)
    finding_id = _make_finding(engine, target_id, severity=Severity.MEDIUM, cve_id="CVE-2024-0001")
    with Session(engine) as session:
        session.add(
            CveEnrichment(
                cve_id="CVE-2024-0001",
                nvd_found=True,
                cvss_vector=V31_WORST,
                cvss_version="3.1",
                cvss_attack_vector="network",
                cvss_attack_complexity="low",
                cvss_privileges_required="none",
                cvss_user_interaction="none",
            )
        )
        session.add(ScoringWeight(workspace_id=ws_id, signal=ScoringSignal.CVSS_EXPLOITABILITY, weight=1.0))
        session.commit()

        finding = session.get(Finding, finding_id)
        contribution = score_breakdown_for_finding(session, finding).contribution(
            ScoringSignal.CVSS_EXPLOITABILITY
        )
    assert contribution.established
    assert contribution.points > 0


def test_decomposition_falls_back_to_reparsing_a_row_written_before_201():
    """Rows cached before the decomposition columns existed have to keep
    scoring, or the exploitability signal would only ever apply to CVEs
    discovered after the upgrade -- this cache is never re-fetched."""
    legacy_row = CveEnrichment(cve_id="CVE-2024-0002", nvd_found=True, cvss_vector=V31_WORST)
    decomposition = cvss_for_enrichment(legacy_row)
    assert decomposition.attack_vector == "network"


def test_decomposition_of_a_missing_enrichment_row_is_unknown():
    assert cvss_for_enrichment(None) == UNKNOWN_CVSS


def test_backfill_writes_the_decomposition_onto_a_legacy_row():
    row = CveEnrichment(cve_id="CVE-2024-0003", nvd_found=True, cvss_vector=V31_WORST)
    assert apply_cvss_decomposition(row) is True
    assert row.cvss_version == "3.1"
    assert row.cvss_attack_vector == "network"
    # Idempotent: a second pass has nothing to write, so the read-path
    # backfill settles after one commit per row instead of writing forever.
    assert apply_cvss_decomposition(row) is False


def test_backfill_leaves_an_undecodable_vector_null_and_does_not_rewrite_it():
    """NULL is how "not established" is spelled in these columns. Writing
    anything else would give scoring a value to treat as benign, and
    returning True would make every read of this row a write."""
    row = CveEnrichment(cve_id="CVE-2024-0004", nvd_found=True, cvss_vector="garbage")
    assert apply_cvss_decomposition(row) is False
    assert row.cvss_version is None
    assert row.cvss_attack_vector is None


def test_backfill_on_a_row_with_no_vector_at_all_is_a_no_op():
    row = CveEnrichment(cve_id="CVE-2024-0005", nvd_found=False)
    assert apply_cvss_decomposition(row) is False
    assert cvss_for_enrichment(row) == UNKNOWN_CVSS


# --------------------------------------------------------------------------
# Re-scoring on rescan. priority_score used to be write-once at creation,
# which was survivable with a fixed formula and is not with a configurable
# one: after a weight change the backlog would hold two scoring regimes at
# once, `ORDER BY priority_score` would compare numbers computed under
# different rules, and the detail view's `stale` flag would never clear.
# --------------------------------------------------------------------------


def _parsed(rule_id="R1", severity=Severity.HIGH, cve_id=None):
    return [
        {
            "rule_id": rule_id,
            "title": "t",
            "description": "",
            "file_path": "app.py",
            "line_start": 3,
            "severity": severity,
            "cve_id": cve_id,
        }
    ]


def _scan_for(engine, target_id, tool="semgrep") -> int:
    from app.models.models import Scan

    with Session(engine) as session:
        scan = Scan(target_id=target_id, tool=tool, branch="main", status="completed")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _ingest(engine, target_id, parsed, tool="semgrep"):
    """Run one ingestion pass the way a real scan would.

    Sessions are opened sequentially, never nested: the in-memory SQLite
    engine is StaticPool-backed (one shared connection), so a nested session
    would be operating on the same connection as its parent.
    """
    from app.core import ingestion
    from app.models.models import Scan

    scan_id = _scan_for(engine, target_id, tool=tool)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        scan = session.get(Scan, scan_id)
        ingestion.ingest_findings(session, target, scan, tool, "main", parsed)


def _stored_scores(engine) -> list[int]:
    with Session(engine) as session:
        return [f.priority_score for f in session.exec(select(Finding)).all()]


def test_a_weight_change_reaches_findings_on_the_next_scan_that_sees_them(engine, monkeypatch):
    """The fix for write-once scoring. Ingest, change a weight, re-ingest the
    same finding, and the stored score must move -- otherwise the workspace
    permanently holds two incompatible scoring regimes."""
    from app.core import ingestion

    # Neither is reached (no cve_id in the batch), but stub them so the test
    # can never touch the network.
    monkeypatch.setattr(ingestion, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(ingestion, "fetch_kev_cve_set", lambda: set())

    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, label="Public", criticality_weight=2)

    _ingest(engine, target_id, _parsed())
    # High severity (4) x criticality 2 x 40, exposure not yet weighted.
    assert _stored_scores(engine) == [320]

    with Session(engine) as session:
        session.add(
            ScoringWeight(workspace_id=ws_id, signal=ScoringSignal.INTERNET_EXPOSURE, weight=1.0)
        )
        session.commit()

    _ingest(engine, target_id, _parsed())

    # Same dedup hash -> still one finding, re-scored rather than duplicated.
    assert _stored_scores(engine) == [320 + INTERNET_EXPOSURE_MAX_POINTS]


def test_rescan_without_a_config_change_leaves_the_score_alone(engine, monkeypatch):
    """Re-scoring must be idempotent, or every scan would churn the number
    and the audit trail with it."""
    from app.core import ingestion

    monkeypatch.setattr(ingestion, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(ingestion, "fetch_kev_cve_set", lambda: set())

    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id, criticality_weight=3)

    scores = []
    for _ in range(3):
        _ingest(engine, target_id, _parsed())
        scores.append(_stored_scores(engine))

    assert scores == [[480], [480], [480]]


def test_ingestion_does_not_enrich_when_the_cve_signals_are_switched_off(engine, monkeypatch):
    """On the shipped baseline both CVE-backed weights are 0, so a scan must
    make exactly the network calls it made before #201 -- the cost of the
    feature arrives when someone enables it, not when they upgrade."""
    from app.core import ingestion

    monkeypatch.setattr(ingestion, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(ingestion, "fetch_kev_cve_set", lambda: set())
    calls = []
    monkeypatch.setattr(ingestion, "warm_cve_enrichment", lambda s, ids: calls.append(list(ids)))

    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    _ingest(engine, target_id, _parsed(cve_id="CVE-2024-9999"), tool="trivy")

    assert calls == []


def test_ingestion_warms_enrichment_once_a_cve_signal_is_weighted(engine, monkeypatch):
    """The other half: a weighted signal whose cache nothing populates is a
    signal that silently cannot fire."""
    from app.core import ingestion

    monkeypatch.setattr(ingestion, "fetch_epss_scores", lambda ids: {})
    monkeypatch.setattr(ingestion, "fetch_kev_cve_set", lambda: set())
    calls = []
    monkeypatch.setattr(ingestion, "warm_cve_enrichment", lambda s, ids: calls.append(list(ids)))

    ws_id = _make_workspace(engine)
    target_id = _make_target(engine, ws_id)
    with Session(engine) as session:
        session.add(
            ScoringWeight(workspace_id=ws_id, signal=ScoringSignal.CVSS_EXPLOITABILITY, weight=1.0)
        )
        session.commit()

    _ingest(engine, target_id, _parsed(cve_id="CVE-2024-9999"), tool="trivy")

    assert calls == [["CVE-2024-9999"]]


def test_warm_up_skips_already_cached_cves_and_respects_its_budget(engine, monkeypatch):
    """NVD's unauthenticated limit is 5 requests / 30s, so an uncapped
    warm-up on a large monorepo's first scan would serialise into hours."""
    from app.core import cve_enrichment as ce

    fetched = []

    def fake_get(session, cve_id):
        fetched.append(cve_id)
        return CveEnrichment(cve_id=cve_id)

    monkeypatch.setattr(ce, "get_cve_enrichment", fake_get)

    with Session(engine) as session:
        session.add(CveEnrichment(cve_id="CVE-0000-0001", nvd_found=True))
        session.commit()

        ids = ["CVE-0000-0001"] + [f"CVE-9999-{i:04d}" for i in range(ce.MAX_ENRICHMENT_LOOKUPS_PER_RUN + 10)]
        count = ce.warm_cve_enrichment(session, ids)

    assert "CVE-0000-0001" not in fetched  # already cached
    assert count == ce.MAX_ENRICHMENT_LOOKUPS_PER_RUN
    assert len(fetched) == ce.MAX_ENRICHMENT_LOOKUPS_PER_RUN


def test_warm_up_survives_an_upstream_failure(engine, monkeypatch):
    """A scan must never fail because NVD is down; the signal just stays
    unestablished, which contributes nothing rather than lowering anything."""
    from app.core import cve_enrichment as ce

    def exploding_get(session, cve_id):
        raise RuntimeError("NVD is down")

    monkeypatch.setattr(ce, "get_cve_enrichment", exploding_get)
    with Session(engine) as session:
        assert ce.warm_cve_enrichment(session, ["CVE-2024-0001"]) == 0
