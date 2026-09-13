"""Configurable risk prioritisation (#201, phases 1-2).

Before this, priority was three hardcoded constants:
`severity_weight x criticality_weight x 40`, floored at 900 for KEV, +160 for
EPSS > 0.5. Good signals, but no install could tell the platform that being
internet-facing matters more to them than CVSS does, and a finding's number
came with no account of where it came from.

This module keeps that formula exactly, and makes it the *baseline* of a
weighted engine with a fixed set of signal slots (`ScoringSignal`). Two
properties it has to hold, both asserted in tests/test_risk_scoring.py:

1. **The baseline reproduces today's scores exactly.** An install that
   configures nothing gets byte-identical numbers to the ones already in its
   database. This is why the three signals this issue adds --- CVSS
   exploitability, internet exposure, fixability --- ship at weight 0.0
   rather than at some sensible-looking default. A scoring change that
   silently re-ranks everyone's backlog on upgrade, moves their SLA
   breaches, and changes what PR Guardrail blocks is not a feature, it is an
   incident. Turning a signal on is a decision an operator makes in
   Admin > Risk Scoring, with the consequence stated.

2. **Nothing ever subtracts.** Every signal below contributes a
   non-negative number of points, weights are clamped to >= 0, and the only
   non-additive operator is a `max()` floor (KEV). This is structural, not a
   convention: there is no code path through which a signal can lower a
   score, so there is no code path through which an *unknown* signal can
   lower a score. That is #201's hard rule, and the same one #246/#243/#253
   keep restating --- "we did not establish X" is never "X is absent".
   Positive evidence of safety is a thing this engine deliberately cannot
   act on yet; the only signal where that would be meaningful is first-party
   reachability, which is phase 3 and depends on #183.

Every computation returns a `ScoreBreakdown`, not a bare int: the score plus
one `SignalContribution` per slot saying what the signal was, whether it was
established at all, and how many points it actually added. #251 set the
standard that a number the platform asserts about someone's risk has to be
explainable rather than asserted; a priority score is the most-looked-at
number in the product and was the least explained.
"""

import logging
from dataclasses import dataclass, field
from math import isfinite
from typing import Mapping

from app.core.cvss import CvssDecomposition
from app.models.models import ScoringSignal, Severity, SEVERITY_WEIGHT

logger = logging.getLogger(__name__)

# --- the original hardcoded constants, now the baseline's calibration ---

# Every finding starts from one "unit"; the base formula is
# BASE_UNIT x severity_weight x criticality_weight, so an Informational
# finding on a criticality-1 target scores exactly BASE_UNIT.
BASE_UNIT = 40
MAX_SCORE = 1000

# KEV is a floor, not a bump: a vulnerability known to be exploited in the
# wild belongs near the top regardless of what the base formula said.
KEV_FLOOR = 900

# EPSS above this probability is worth roughly one severity tier at mid
# criticality. Applied only when KEV did not already fire (KEV is the
# stronger, observed-in-the-wild claim; EPSS is a prediction).
EPSS_BUMP = 160
EPSS_NOTABLE_THRESHOLD = 0.5

# --- the signals this issue adds, all baselined off ---

# Full marks here means "network-reachable, low complexity, no privileges,
# no user interaction" --- the shape of a CVE that gets mass-exploited.
CVSS_EXPLOITABILITY_MAX_POINTS = 200
# Reserved for a target positively recorded as internet-facing.
INTERNET_EXPOSURE_MAX_POINTS = 180
# #246: a finding with an upgrade available is one someone can actually
# close today, and surfacing those above the wall of un-actionable Criticals
# is the point of that verdict existing.
FIXABILITY_POINTS = 120


BASELINE_WEIGHTS: dict[ScoringSignal, float] = {
    # The three signals that were already in the formula, at the weight that
    # reproduces it.
    ScoringSignal.SEVERITY: 1.0,
    ScoringSignal.BUSINESS_CRITICALITY: 1.0,
    ScoringSignal.KEV: 1.0,
    ScoringSignal.EPSS: 1.0,
    # The three this issue adds. 0.0 on purpose --- see property (1) in the
    # module docstring. They are configuration that exists and works, not
    # behaviour anyone gets without asking for it.
    ScoringSignal.CVSS_EXPLOITABILITY: 0.0,
    ScoringSignal.INTERNET_EXPOSURE: 0.0,
    ScoringSignal.FIXABILITY: 0.0,
}

SIGNAL_LABELS: dict[ScoringSignal, str] = {
    ScoringSignal.SEVERITY: "Tool severity",
    ScoringSignal.BUSINESS_CRITICALITY: "Business criticality",
    ScoringSignal.CVSS_EXPLOITABILITY: "CVSS exploitability",
    ScoringSignal.EPSS: "EPSS",
    ScoringSignal.KEV: "CISA KEV",
    ScoringSignal.INTERNET_EXPOSURE: "Internet exposure",
    ScoringSignal.FIXABILITY: "Fixability",
}

SIGNAL_DESCRIPTIONS: dict[ScoringSignal, str] = {
    ScoringSignal.SEVERITY: (
        "The severity the scanner itself reported, 1 (Informational) to 5 (Critical). "
        "Multiplies the base score; at weight 0 every finding starts equal regardless of severity."
    ),
    ScoringSignal.BUSINESS_CRITICALITY: (
        "The target's criticality weight (1-5), the answer to \"how much does this repo matter\". "
        "Multiplies the base score alongside severity."
    ),
    ScoringSignal.CVSS_EXPLOITABILITY: (
        "Attack Vector, Attack Complexity, Privileges Required and User Interaction, decomposed "
        "from the CVE's CVSS vector. Only CVE-backed findings carry one; a finding with no "
        "decodable vector is unknown and contributes nothing rather than being treated as hard to exploit."
    ),
    ScoringSignal.EPSS: (
        "FIRST's predicted probability that this CVE is exploited in the next 30 days. "
        f"Applies above {int(EPSS_NOTABLE_THRESHOLD * 100)}%, and only when KEV has not already fired."
    ),
    ScoringSignal.KEV: (
        "Listed in CISA's Known Exploited Vulnerabilities catalog. Raises the score to a floor "
        "rather than adding to it: observed exploitation outranks whatever the base formula said."
    ),
    ScoringSignal.INTERNET_EXPOSURE: (
        "Whether the target is reachable from the public internet, read from its label and "
        "environment. Only a target positively recorded as public gets the full uplift; a target "
        "with nothing recorded is unknown and is never penalised for it."
    ),
    ScoringSignal.FIXABILITY: (
        "Whether an upgrade that resolves this finding is already available (#246). Raises findings "
        "someone can actually close today above ones with no fix to apply."
    ),
}

# How each slot enters the score. The three behave differently enough that a
# UI describing one as another is simply wrong: a "floor" does not add
# `max_points`, it raises the score *to* a level, so what KEV is worth
# depends entirely on where the finding already was (260 points to a finding
# at 640; nothing at all to one already above 900).
CONTRIBUTION_MULTIPLIER = "multiplier"  # scales a factor of the base product
CONTRIBUTION_POINTS = "points"          # adds up to max_points x weight
CONTRIBUTION_FLOOR = "floor"            # raises the score to max_points x weight

SIGNAL_CONTRIBUTION: dict[ScoringSignal, str] = {
    ScoringSignal.SEVERITY: CONTRIBUTION_MULTIPLIER,
    ScoringSignal.BUSINESS_CRITICALITY: CONTRIBUTION_MULTIPLIER,
    ScoringSignal.CVSS_EXPLOITABILITY: CONTRIBUTION_POINTS,
    ScoringSignal.EPSS: CONTRIBUTION_POINTS,
    ScoringSignal.KEV: CONTRIBUTION_FLOOR,
    ScoringSignal.INTERNET_EXPOSURE: CONTRIBUTION_POINTS,
    ScoringSignal.FIXABILITY: CONTRIBUTION_POINTS,
}

# Points each slot can contribute at weight 1.0, for the Admin UI to show
# what a weight is a multiplier *of*. None for the two multiplicative slots,
# whose contribution is not a fixed ceiling.
SIGNAL_MAX_POINTS: dict[ScoringSignal, int | None] = {
    ScoringSignal.SEVERITY: None,
    ScoringSignal.BUSINESS_CRITICALITY: None,
    ScoringSignal.CVSS_EXPLOITABILITY: CVSS_EXPLOITABILITY_MAX_POINTS,
    ScoringSignal.EPSS: EPSS_BUMP,
    ScoringSignal.KEV: KEV_FLOOR,
    ScoringSignal.INTERNET_EXPOSURE: INTERNET_EXPOSURE_MAX_POINTS,
    ScoringSignal.FIXABILITY: FIXABILITY_POINTS,
}


# --- internet exposure (#201 phase 2) ---
#
# Target.label and Target.environment are free text on purpose (#251: every
# org names its environments differently, and an enum would force a rename
# on anyone who disagreed). So these are recognition sets, matched
# case-insensitively, and anything unrecognised is *unknown* rather than
# assumed private. Extending them is a one-line change; mis-scoring an
# unrecognised value as safe is not recoverable from.

PUBLIC_LABELS = frozenset({"public", "external", "internet", "internet-facing", "edge", "dmz"})
PRIVATE_LABELS = frozenset({"internal", "private", "intranet"})
PRODUCTION_VALUES = frozenset({"prod", "production", "live"})
NON_PRODUCTION_VALUES = frozenset({"dev", "development", "staging", "stage", "test", "testing", "qa", "sandbox", "local"})

# A production target is more likely to be reachable than a dev one, but
# "runs in production" is a materially weaker claim than "is labelled
# Public" --- plenty of production services sit entirely behind a VPN. It
# gets a partial uplift rather than the full one, and the breakdown says
# which of the two fired.
PRODUCTION_EXPOSURE_FACTOR = 0.5


@dataclass(frozen=True)
class ExposureSignal:
    """How internet-exposed a target was established to be.

    `established=False` is the "nothing recorded" case and is distinct from
    `factor=0.0, established=True` ("recorded as internal"). Both contribute
    zero points --- nothing in this engine subtracts --- but the breakdown
    has to say which one it was, because "we don't know" and "we checked and
    it's internal" are different sentences to show a person.
    """

    factor: float
    established: bool
    detail: str


def resolve_exposure(label: str | None, environment: str | None) -> ExposureSignal:
    """Read internet exposure off a target's #251 metadata.

    Label wins over environment, and the label is resolved *completely*
    before environment is consulted at all: `label="Public"` and
    `label="Internal"` are both someone explicitly stating the network
    posture, while environment is a deployment stage that merely correlates
    with it. A production service behind a VPN is an ordinary thing, so
    `label="Internal", environment="production"` has to read as internal.

    An earlier revision checked production before the private labels, which
    inverted exactly that case: an explicitly Internal target picked up the
    production uplift and the explanation never mentioned the label
    contradicting it.
    """
    raw_label = (label or "").strip()
    raw_env = (environment or "").strip()
    lowered_label = raw_label.lower()
    lowered_env = raw_env.lower()

    if lowered_label in PUBLIC_LABELS:
        return ExposureSignal(1.0, True, f'target is labelled "{raw_label}" (internet-facing)')

    if lowered_label in PRIVATE_LABELS:
        detail = f'target is labelled "{raw_label}" (not internet-facing); no exposure uplift'
        if lowered_env in PRODUCTION_VALUES:
            # Name the tension rather than resolving it silently. Someone
            # looking at a production service that scored no exposure needs
            # to see that the label is why, so they can fix the label if it
            # is the thing that is wrong.
            detail = (
                f'target is labelled "{raw_label}" (not internet-facing), which wins over its '
                f'"{raw_env}" environment; no exposure uplift'
            )
        return ExposureSignal(0.0, True, detail)

    env_is_production = lowered_env in PRODUCTION_VALUES
    label_is_production = lowered_label in PRODUCTION_VALUES
    if env_is_production or label_is_production:
        # Name the field that actually matched. An earlier `raw_env or
        # raw_label` rendered label="prod", environment="staging" as
        # 'target runs in "staging"; production' -- a sentence that
        # contradicts itself, in the panel whose entire job is that the
        # detail is true.
        if env_is_production and label_is_production:
            source = f'target is labelled "{raw_label}" and runs in "{raw_env}"'
        elif env_is_production:
            source = f'target runs in "{raw_env}"'
        elif lowered_env in NON_PRODUCTION_VALUES:
            # The label says production and the environment says otherwise.
            # Label wins (see this function's docstring), but showing only
            # the winner would hide a disagreement someone probably wants to
            # go and resolve.
            source = f'target is labelled "{raw_label}", which wins over its "{raw_env}" environment'
        else:
            source = f'target is labelled "{raw_label}"'
        return ExposureSignal(
            PRODUCTION_EXPOSURE_FACTOR,
            True,
            f"{source}; production, but not positively recorded as internet-facing",
        )

    if lowered_env in NON_PRODUCTION_VALUES:
        recorded = " / ".join(part for part in (raw_label, raw_env) if part)
        return ExposureSignal(0.0, True, f"target is recorded as {recorded}; no exposure uplift")

    if raw_label or raw_env:
        recorded = " / ".join(part for part in (raw_label, raw_env) if part)
        return ExposureSignal(
            0.0,
            False,
            f'target label/environment ("{recorded}") does not establish internet exposure either way',
        )

    return ExposureSignal(0.0, False, "no label or environment recorded for this target")


# --- breakdown types ---


@dataclass(frozen=True)
class SignalContribution:
    """One signal slot's account of itself.

    `established` is the load-bearing field. `points == 0` happens for two
    completely different reasons --- the signal was established and simply
    did not apply ("EPSS is 3%, below the threshold"), or it was never
    established at all ("this finding has no CVE to look up") --- and
    collapsing them would reintroduce exactly the confusion #246 exists to
    prevent. The UI renders the two differently.
    """

    signal: ScoringSignal
    label: str
    weight: float
    points: int
    established: bool
    detail: str


@dataclass(frozen=True)
class ScoreBreakdown:
    """A priority score and the complete account of how it got there.

    `base_points + sum(c.points for c in contributions) == score`, exactly,
    unless `capped` is True (the raw total exceeded MAX_SCORE and the
    remainder was truncated). Contributions are rounded progressively rather
    than independently so that invariant holds and the explanation never
    shows numbers that do not add up.
    """

    score: int
    base_points: int
    contributions: list[SignalContribution] = field(default_factory=list)
    capped: bool = False
    max_score: int = MAX_SCORE

    def contribution(self, signal: ScoringSignal) -> SignalContribution | None:
        for c in self.contributions:
            if c.signal == signal:
                return c
        return None


# The bound a weight is clamped into. Lives here, next to the clamp that
# enforces it, rather than in the API module that also validates against it:
# the API is not the only way a row reaches this table (a migration, a
# support script, or a direct psql session all bypass it), and a bound that
# only one writer honours is not a bound.
MIN_WEIGHT = 0.0
MAX_WEIGHT = 5.0


def resolve_weights(overrides: Mapping[ScoringSignal, float] | None = None) -> dict[ScoringSignal, float]:
    """Merge overrides onto the shipped baseline, clamped into
    [MIN_WEIGHT, MAX_WEIGHT] with non-finite values discarded.

    The low clamp is not defensive tidiness: a negative weight would turn a
    signal into a penalty, and the moment any signal can subtract, an
    unknown signal can lower a score by being absent. The guarantee is worth
    more than the flexibility.

    The high clamp and the NaN/infinity check exist because Postgres
    `float8` happily stores `'Infinity'` and `'NaN'`, and this table is
    writable by anything holding a DB connection. An infinite weight is not
    an absurdly-high priority, it is `round(inf)` raising OverflowError
    inside `compute_score_breakdown` -- which would 500 every scoring call,
    every findings list and every scan in that workspace. Scoring must
    degrade to "the operator configured something silly" rather than to a
    stack trace, so garbage is dropped here and the baseline stands in.

    Every discard is logged, because the symptom is otherwise invisible: a
    dropped row scores exactly like an unconfigured one, which looks
    completely normal. Volume is bounded -- `workspace_scoring_weights`
    resolves raw rows once per ingestion run or request, and the second
    pass this function makes from inside `compute_score_breakdown` is over
    an already-clean dict, so it logs nothing.
    """
    weights = dict(BASELINE_WEIGHTS)
    for signal, value in (overrides or {}).items():
        if signal not in weights:
            logger.warning(
                "Ignoring scoring weight for unrecognised signal %r; scoring on the baseline set", signal
            )
            continue
        try:
            candidate = float(value)
        except (TypeError, ValueError):
            # Logged, not swallowed. A discarded row is invisible by
            # construction -- the score it produces is simply the baseline's,
            # which looks entirely normal -- so without a line here the only
            # evidence that a workspace is not scoring the way its
            # configuration says would be someone reading the table by hand.
            logger.warning(
                "Scoring weight for %s is not a number (%r); falling back to the baseline %.2f",
                signal.value, value, weights[signal],
            )
            continue
        if not isfinite(candidate):
            # NaN or +/-inf. Deliberately the baseline, not MAX_WEIGHT:
            # silently promoting a corrupt row to the strongest possible
            # setting would be a worse outcome than ignoring it.
            logger.warning(
                "Scoring weight for %s is not finite (%r); falling back to the baseline %.2f. "
                "Postgres float8 accepts 'Infinity'/'NaN', so this row was almost certainly "
                "written outside the API, which rejects both.",
                signal.value, value, weights[signal],
            )
            continue
        clamped = min(MAX_WEIGHT, max(MIN_WEIGHT, candidate))
        if clamped != candidate:
            logger.warning(
                "Scoring weight for %s (%.4f) is outside [%.1f, %.1f]; clamped to %.2f",
                signal.value, candidate, MIN_WEIGHT, MAX_WEIGHT, clamped,
            )
        weights[signal] = clamped
    return weights


def compute_score_breakdown(
    severity: Severity,
    target_criticality_weight: int,
    epss_score: float | None = None,
    kev_listed: bool = False,
    *,
    cvss: CvssDecomposition | None = None,
    cve_id: str | None = None,
    target_label: str | None = None,
    target_environment: str | None = None,
    target_owner: str | None = None,
    fixability: str | None = None,
    weights: Mapping[ScoringSignal, float] | None = None,
) -> ScoreBreakdown:
    """Score one finding and explain the result.

    Every keyword after `kev_listed` is a signal that may legitimately be
    absent, and `None` means absent in every one of them. There is no
    sentinel that means "we checked and it was fine"; where that distinction
    matters (exposure, fixability) it is carried in the contribution's
    `established` flag, not in the points.

    `cve_id` is the one argument that affects no arithmetic at all. It is
    here purely so the two CVE-backed signals can say *why* they are
    unknown -- "this finding has no CVE" and "this CVE has not been enriched
    yet" are the difference between a signal that can never fire for a
    finding and one that simply has not fired yet, and a reader deciding
    whether to weight the signal needs to tell them apart.
    """
    w = resolve_weights(weights)
    contributions: list[SignalContribution] = []

    # --- base: severity x criticality ---
    #
    # Today's formula is a product, not a sum, and it has to stay one for
    # the baseline to reproduce exactly. A weight therefore scales each
    # factor's *excess over 1*:
    #
    #     effective = 1 + (raw - 1) * weight
    #
    # At weight 1.0 that is the raw factor untouched, so the product is
    # 40 x severity x criticality exactly as before. At weight 0.0 the
    # factor collapses to 1 and stops influencing the score at all, which
    # is what "switch this signal off" should mean for a multiplier.
    severity_weight = SEVERITY_WEIGHT[severity]
    criticality = max(1, min(5, target_criticality_weight))
    effective_severity = 1 + (severity_weight - 1) * w[ScoringSignal.SEVERITY]
    effective_criticality = 1 + (criticality - 1) * w[ScoringSignal.BUSINESS_CRITICALITY]

    # Attributed progressively so the displayed parts sum to the displayed
    # total: severity's points are what it adds over the bare unit, and
    # criticality's are what it adds on top of that.
    running = BASE_UNIT
    after_severity = round(BASE_UNIT * effective_severity)
    severity_points = after_severity - running
    running = after_severity
    after_criticality = round(BASE_UNIT * effective_severity * effective_criticality)
    criticality_points = after_criticality - running
    running = after_criticality

    contributions.append(
        SignalContribution(
            signal=ScoringSignal.SEVERITY,
            label=SIGNAL_LABELS[ScoringSignal.SEVERITY],
            weight=w[ScoringSignal.SEVERITY],
            points=severity_points,
            established=True,
            detail=f"{severity.value} (severity weight {severity_weight} of 5)",
        )
    )

    criticality_detail = f"target criticality weight {criticality} of 5"
    # #251's metadata is why the criticality number is what it is, so the
    # explanation carries it rather than leaving the weight as a bare
    # assertion nobody can argue with.
    context = ", ".join(
        part
        for part in (
            f"owner: {target_owner}" if target_owner else "",
            f"environment: {target_environment}" if target_environment else "",
            f"label: {target_label}" if target_label else "",
        )
        if part
    )
    if context:
        criticality_detail = f"{criticality_detail} ({context})"
    contributions.append(
        SignalContribution(
            signal=ScoringSignal.BUSINESS_CRITICALITY,
            label=SIGNAL_LABELS[ScoringSignal.BUSINESS_CRITICALITY],
            weight=w[ScoringSignal.BUSINESS_CRITICALITY],
            points=criticality_points,
            established=True,
            detail=criticality_detail,
        )
    )

    capped = running > MAX_SCORE
    score = min(MAX_SCORE, running)

    # --- KEV: a floor, applied before EPSS ---
    kev_points = 0
    if kev_listed:
        floor = min(MAX_SCORE, round(KEV_FLOOR * w[ScoringSignal.KEV]))
        raised = max(score, floor)
        kev_points = raised - score
        score = raised
        kev_established = True
        kev_detail = (
            f"listed in CISA's Known Exploited Vulnerabilities catalog; raises the score to a floor of {floor}"
            if kev_points
            else "listed in CISA's Known Exploited Vulnerabilities catalog; the base score already exceeds the floor"
        )
    else:
        # Deliberately not "not known to be exploited". fetch_kev_cve_set()
        # returns an empty set when the CISA feed is unreachable, so
        # kev_listed=False is the absence of a hit, not a verified negative,
        # and the wording must not overstate it.
        kev_established = False
        kev_detail = "not present in the KEV data available when this finding was ingested"
    contributions.append(
        SignalContribution(
            signal=ScoringSignal.KEV,
            label=SIGNAL_LABELS[ScoringSignal.KEV],
            weight=w[ScoringSignal.KEV],
            points=kev_points,
            established=kev_established,
            detail=kev_detail,
        )
    )

    # --- EPSS: only when KEV did not fire (preserves the original `elif`) ---
    epss_points = 0
    if epss_score is None:
        epss_established = False
        epss_detail = "no EPSS score resolved for this finding"
    elif kev_listed:
        epss_established = True
        epss_detail = f"EPSS {epss_score:.0%}; superseded by the KEV floor above"
    elif epss_score > EPSS_NOTABLE_THRESHOLD:
        epss_established = True
        bump = round(EPSS_BUMP * w[ScoringSignal.EPSS])
        raised = min(MAX_SCORE, score + bump)
        epss_points = raised - score
        capped = capped or (score + bump) > MAX_SCORE
        score = raised
        epss_detail = f"EPSS {epss_score:.0%} exceeds the {EPSS_NOTABLE_THRESHOLD:.0%} threshold"
    else:
        epss_established = True
        epss_detail = f"EPSS {epss_score:.0%} is below the {EPSS_NOTABLE_THRESHOLD:.0%} threshold"
    contributions.append(
        SignalContribution(
            signal=ScoringSignal.EPSS,
            label=SIGNAL_LABELS[ScoringSignal.EPSS],
            weight=w[ScoringSignal.EPSS],
            points=epss_points,
            established=epss_established,
            detail=epss_detail,
        )
    )

    # --- the additive signals this issue adds ---
    #
    # Each is applied through _add() so a signal that runs into the 1000-cap
    # reports the points it actually contributed rather than the points it
    # would have liked to.

    def _add(points: int) -> int:
        nonlocal score, capped
        raised = min(MAX_SCORE, score + points)
        actual = raised - score
        if points > actual:
            capped = True
        score = raised
        return actual

    exploitability = cvss.exploitability() if cvss is not None else None
    if exploitability is None:
        cvss_points = 0
        cvss_established = False
        # "Unknown" has several distinct causes here and a reader deciding
        # whether to trust (or weight) this signal needs to know which one
        # they hit. A finding with no CVE will never establish this no
        # matter what; one whose CVE simply has not been enriched yet will,
        # once it is. Collapsing those into one sentence is how a signal
        # that structurally cannot fire looks identical to one that merely
        # has not fired yet.
        if cvss is not None and not cvss.is_unknown:
            # Decoded, but no comparable sub-score. Only v2 reaches this
            # today (a v3/v4 vector with any decoded metric always yields a
            # number), but the wording degrades to something still true if
            # another version is ever carved out the same way, rather than
            # asserting "v2" about a vector that is not one.
            cvss_detail = (
                f"CVSS {cvss.version} vector decoded ({cvss.describe()}), but v2 carries no "
                "Privileges Required or User Interaction metric, so it yields no exploitability "
                "score comparable with v3/v4 findings"
                if cvss.version == "2.0"
                else (
                    f"CVSS {cvss.version or 'vector'} decoded ({cvss.describe()}), but it yields no "
                    "exploitability score comparable with other findings"
                )
            )
        elif cve_id:
            cvss_detail = (
                f"{cve_id} has no CVSS vector cached yet; NVD enrichment has not run for it, so "
                "exploitability is unknown rather than low"
            )
        else:
            cvss_detail = (
                "this finding carries no CVE, so there is no CVSS vector to decompose; unknown, "
                "not benign"
            )
    else:
        cvss_established = True
        cvss_points = _add(round(CVSS_EXPLOITABILITY_MAX_POINTS * w[ScoringSignal.CVSS_EXPLOITABILITY] * exploitability))
        version = f"CVSS {cvss.version} " if cvss.version else "CVSS "
        cvss_detail = f"{version}{cvss.describe()} (exploitability {exploitability:.2f} of 1.00)"
    contributions.append(
        SignalContribution(
            signal=ScoringSignal.CVSS_EXPLOITABILITY,
            label=SIGNAL_LABELS[ScoringSignal.CVSS_EXPLOITABILITY],
            weight=w[ScoringSignal.CVSS_EXPLOITABILITY],
            points=cvss_points,
            established=cvss_established,
            detail=cvss_detail,
        )
    )

    exposure = resolve_exposure(target_label, target_environment)
    exposure_points = _add(round(INTERNET_EXPOSURE_MAX_POINTS * w[ScoringSignal.INTERNET_EXPOSURE] * exposure.factor))
    contributions.append(
        SignalContribution(
            signal=ScoringSignal.INTERNET_EXPOSURE,
            label=SIGNAL_LABELS[ScoringSignal.INTERNET_EXPOSURE],
            weight=w[ScoringSignal.INTERNET_EXPOSURE],
            points=exposure_points,
            established=exposure.established,
            detail=exposure.detail,
        )
    )

    # Compared against app.core.fixability's literals rather than importing
    # them: that module reaches for the ORM, and this one is deliberately
    # pure (no session, no I/O) so it stays trivially testable. The values
    # are part of the API contract already (the findings list filters on
    # them), so they are not going to drift quietly.
    fix_points = 0
    if fixability == "fixable":
        fix_established = True
        fix_points = _add(round(FIXABILITY_POINTS * w[ScoringSignal.FIXABILITY]))
        fix_detail = "an upgrade that resolves this is available, so this one can be closed today"
    elif fixability == "no_known_fix":
        fix_established = True
        fix_detail = "the advisory lists no fixed version; no uplift, but no penalty either"
    else:
        # "unknown", None, or anything unrecognised. Most SAST and secrets
        # findings carry no CVE to look up, so this is the common case and
        # must read as an absence of data, not a verdict. Same split as the
        # CVSS detail above: never-will-establish reads differently from
        # has-not-established-yet.
        fix_established = False
        fix_detail = (
            f"{cve_id} has not been enriched from OSV yet, so whether a fix exists is unknown"
            if cve_id
            else "this finding carries no CVE advisory to resolve a fixed version from"
        )
    contributions.append(
        SignalContribution(
            signal=ScoringSignal.FIXABILITY,
            label=SIGNAL_LABELS[ScoringSignal.FIXABILITY],
            weight=w[ScoringSignal.FIXABILITY],
            points=fix_points,
            established=fix_established,
            detail=fix_detail,
        )
    )

    return ScoreBreakdown(
        score=score,
        base_points=BASE_UNIT,
        contributions=contributions,
        capped=capped,
    )


def compute_priority_score(
    severity: Severity,
    target_criticality_weight: int,
    epss_score: float | None = None,
    kev_listed: bool = False,
    **signals,
) -> int:
    """
    Base: Severity Weight (1-5) * Target Criticality Weight (1-5) * 40  -> max 1000.

    Exploitability modifier:
      - KEV-listed (known exploited in the wild) -> floor of 900.
      - EPSS > 0.5 (high real-world exploit probability) -> bump one severity tier's worth.

    Unchanged in behaviour: with no `weights` passed (or the shipped
    baseline passed explicitly) this returns exactly what it returned before
    #201. Callers that want the account of *why* --- the findings API, the
    Admin scoring surface --- should call compute_score_breakdown() instead
    and read `.score` off it; this wrapper exists because the ingestion
    paths only ever needed the number.
    """
    return compute_score_breakdown(
        severity,
        target_criticality_weight,
        epss_score=epss_score,
        kev_listed=kev_listed,
        **signals,
    ).score
