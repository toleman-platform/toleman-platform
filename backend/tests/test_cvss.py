"""CVSS vector decomposition (#201 phase 1).

The load-bearing behaviour is not "does it parse a well-formed v3.1 vector"
-- it is what happens when it cannot. An absent, truncated or nonsense
vector has to come back as *unknown*, with a `None` exploitability, and must
never be handed to scoring as a low-but-real value. Treating "we could not
read this" as "this is hard to exploit" is the same class of false statement
as reporting an unrun scan as clean (#243/#246/#253), and it is silent,
which makes it worse.
"""

import pytest

from app.core.cvss import (
    UNKNOWN_CVSS,
    CvssDecomposition,
    parse_cvss_vector,
)

# Real vectors, copied in the exact shape NVD and OSV emit them.
V31_WORST = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_LOCAL = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
V30_NETWORK = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
V40_WORST = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V40_PASSIVE_UI = "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
V2_VECTOR = "AV:N/AC:M/Au:N/C:P/I:P/A:P"


# --- v3.x ---


def test_parses_v31_base_metrics():
    d = parse_cvss_vector(V31_WORST)
    assert d.version == "3.1"
    assert d.attack_vector == "network"
    assert d.attack_complexity == "low"
    assert d.privileges_required == "none"
    assert d.user_interaction == "none"


def test_parses_v31_hard_to_exploit_metrics():
    d = parse_cvss_vector(V31_LOCAL)
    assert (d.attack_vector, d.attack_complexity) == ("local", "high")
    assert (d.privileges_required, d.user_interaction) == ("high", "required")


def test_parses_v30():
    d = parse_cvss_vector(V30_NETWORK)
    assert d.version == "3.0"
    assert d.attack_vector == "network"
    assert d.privileges_required == "low"


# --- v4.0 ---


def test_parses_v40_base_metrics():
    d = parse_cvss_vector(V40_WORST)
    assert d.version == "4.0"
    assert d.attack_vector == "network"
    assert d.attack_complexity == "low"
    assert d.privileges_required == "none"
    assert d.user_interaction == "none"


def test_parses_v40_passive_user_interaction():
    """v4.0 split v3's UI:R into Passive and Active; both must decode, and
    neither may be mistaken for UI:N."""
    d = parse_cvss_vector(V40_PASSIVE_UI)
    assert d.user_interaction == "passive"
    assert d.attack_vector == "adjacent"


def test_v40_attack_requirements_metric_is_not_mistaken_for_a_base_metric():
    """AT (Attack Requirements) is new in v4 and is not one of the four
    slots. It must not leak into any of them."""
    d = parse_cvss_vector(V40_PASSIVE_UI)
    assert d.attack_complexity == "high"  # AC:H, not AT:P


# --- v2, which is genuinely in this database ---


def test_parses_v2_partially_and_admits_what_it_cannot_know():
    """app.core.nvd falls back to cvssMetricV2, so v2 vectors are already
    stored. v2 has no PR or UI metric; those stay unknown rather than being
    invented from its Au (Authentication) metric, which is a different
    thing."""
    d = parse_cvss_vector(V2_VECTOR)
    assert d.version == "2.0"
    assert d.attack_vector == "network"
    assert d.attack_complexity == "medium"
    assert d.privileges_required is None
    assert d.user_interaction is None


def test_v2_yields_no_exploitability_score_at_all():
    """v2 decodes for display but must not produce a sub-score.

    A mean over {AV, AC} is not the same quantity as a mean over
    {AV, AC, PR, UI}, and the engine ranks these against each other. Scoring
    v2 on its own two metrics gave `AV:N/AC:L/Au:*` a perfect 1.00 where the
    v3 equivalent `AV:N/AC:L/PR:H/UI:R` scores 0.68 -- and since nvd.py falls
    back to v2 precisely for older CVEs, enabling the signal would have
    floated that entire cohort above comparable modern ones.
    """
    v2 = parse_cvss_vector("AV:N/AC:L/Au:M/C:P/I:P/A:P")
    assert v2.attack_vector == "network"  # still decoded, for display
    assert not v2.is_unknown
    assert v2.exploitability() is None  # but not scoreable

    v3_counterpart = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:R")
    assert v3_counterpart.exploitability() is not None
    # The bug was v2 outscoring its stricter v3 counterpart.
    assert not (v2.exploitability() or 0) > v3_counterpart.exploitability()


# --- malformed input: the part that matters ---


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "not a vector at all",
        "CVSS:3.1",  # prefix only, no metrics
        "CVSS:3.1/",
        "/////",
        "AV/AC/PR/UI",  # keys with no values
        "CVSS:3.1/AV:Z/AC:Q/PR:9/UI:!",  # values outside the vocabulary
        "CVSS:yes/AV:banana",
        "AV:",
    ],
)
def test_unparseable_vectors_are_unknown_not_benign(raw):
    d = parse_cvss_vector(raw)
    assert d == UNKNOWN_CVSS
    assert d.is_unknown
    # The whole point: None, never 0.0. A caller that sees 0.0 would treat
    # this CVE as established-and-hard-to-exploit.
    assert d.exploitability() is None


def test_non_string_input_does_not_raise():
    assert parse_cvss_vector(12345) == UNKNOWN_CVSS  # type: ignore[arg-type]


def test_version_prefix_alone_does_not_count_as_established():
    """A vector whose prefix parsed but whose metrics did not is exactly as
    unknown as no vector, and must not carry a version forward that makes it
    look otherwise."""
    d = parse_cvss_vector("CVSS:3.1/S:U/C:H/I:H/A:H")
    assert d.version is None
    assert d.is_unknown


def test_truncated_vector_keeps_only_what_it_established():
    d = parse_cvss_vector("CVSS:3.1/AV:N/AC:L")
    assert d.attack_vector == "network"
    assert d.attack_complexity == "low"
    assert d.privileges_required is None
    assert d.user_interaction is None
    assert not d.is_unknown


def test_environmental_overrides_are_ignored_not_substituted():
    """MAV/MAC/MPR/MUI are an assessor's local re-scoring, and an exact key
    match is what stops MAV:L being read as AV:L."""
    d = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/MAV:P/MAC:H/MPR:H/MUI:R")
    assert d.attack_vector == "network"
    assert d.attack_complexity == "low"
    assert d.privileges_required == "none"
    assert d.user_interaction == "none"


def test_parsing_is_case_insensitive():
    assert parse_cvss_vector("cvss:3.1/av:n/ac:l/pr:n/ui:n").attack_vector == "network"


# --- exploitability sub-score ---


def test_worst_case_vector_scores_full_exploitability():
    assert parse_cvss_vector(V31_WORST).exploitability() == pytest.approx(1.0)


def test_harder_to_exploit_vector_scores_lower():
    assert parse_cvss_vector(V31_LOCAL).exploitability() < parse_cvss_vector(V31_WORST).exploitability()


def test_exploitability_averages_only_the_metrics_we_established():
    """Partial knowledge is scored on what is known, not on a product with
    unknowns silently filled in. AV:N alone is 1.0, so a missing metric can
    never drag a network-reachable CVE down the list."""
    d = parse_cvss_vector("CVSS:3.1/AV:N")
    assert d.exploitability() == pytest.approx(1.0)


def test_the_mean_is_not_monotonic_in_how_much_was_decoded():
    """Pinned as known and accepted behaviour, not asserted as a virtue.

    Averaging over a different metric set each time means decoding *more* of
    a hard-to-exploit vector can raise its sub-score: AV:P alone is 0.15,
    the full AV:P/AC:H/PR:H/UI:R is 0.7875. An earlier comment claimed
    partial decoding always "errs upward", which is only true for the
    network-reachable case. NVD makes all four base metrics mandatory, so
    within real v3/v4 advisories this never arises -- it is a property of
    truncated input. The property that actually matters is the next test.
    """
    partial = parse_cvss_vector("CVSS:3.1/AV:P").exploitability()
    full = parse_cvss_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R").exploitability()
    assert partial == pytest.approx(0.15)
    assert full > partial


def test_partial_vector_is_never_worse_than_no_vector():
    """The guarantee the failsafe rule actually needs: any decoded vector
    produces a sub-score in [0, 1], and an undecodable one produces None,
    which the engine turns into a zero-point contribution. So partial
    knowledge can only ever add."""
    for raw in (
        "CVSS:3.1/AV:P",
        "CVSS:3.1/AV:P/AC:H",
        "CVSS:3.1/AV:P/AC:H/PR:H",
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N",
    ):
        score = parse_cvss_vector(raw).exploitability()
        assert score is not None and 0.0 <= score <= 1.0
    assert parse_cvss_vector("nonsense").exploitability() is None


def test_exploitability_is_none_when_nothing_is_known():
    assert CvssDecomposition().exploitability() is None


def test_known_metrics_excludes_unestablished_ones():
    d = parse_cvss_vector("CVSS:3.1/AV:N/AC:L")
    assert set(d.known_metrics) == {"attack_vector", "attack_complexity"}


def test_describe_names_only_what_is_known():
    described = parse_cvss_vector("CVSS:3.1/AV:N/AC:L").describe()
    assert "Attack Vector: network" in described
    assert "Privileges Required" not in described


def test_describe_of_unknown_says_so():
    assert "no CVSS metrics decoded" in UNKNOWN_CVSS.describe()
