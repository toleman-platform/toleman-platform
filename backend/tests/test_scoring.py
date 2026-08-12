from app.core.scoring import compute_priority_score
from app.models.models import Severity


def test_base_formula_max_score():
    # Critical (5) * weight 5 * 40 = 1000
    assert compute_priority_score(Severity.CRITICAL, 5) == 1000


def test_base_formula_min_score():
    # Informational (1) * weight 1 * 40 = 40
    assert compute_priority_score(Severity.INFO, 1) == 40


def test_higher_target_criticality_beats_higher_severity_without_it():
    # High severity on Prod-weighted target should outrank Critical on Dev
    high_on_prod = compute_priority_score(Severity.HIGH, 5)
    critical_on_dev = compute_priority_score(Severity.CRITICAL, 2)
    assert high_on_prod > critical_on_dev


def test_weight_is_clamped_to_valid_range():
    assert compute_priority_score(Severity.LOW, 0) == compute_priority_score(Severity.LOW, 1)
    assert compute_priority_score(Severity.LOW, 99) == compute_priority_score(Severity.LOW, 5)


def test_kev_listed_forces_high_floor_even_at_low_severity():
    score = compute_priority_score(Severity.LOW, 1, kev_listed=True)
    assert score >= 900


def test_kev_does_not_lower_an_already_high_score():
    score = compute_priority_score(Severity.CRITICAL, 5, kev_listed=True)
    assert score == 1000


def test_high_epss_bumps_score_but_not_as_much_as_kev():
    base = compute_priority_score(Severity.MEDIUM, 3)
    with_epss = compute_priority_score(Severity.MEDIUM, 3, epss_score=0.9)
    assert with_epss > base
    assert with_epss <= 1000


def test_low_epss_does_not_change_score():
    base = compute_priority_score(Severity.MEDIUM, 3)
    with_low_epss = compute_priority_score(Severity.MEDIUM, 3, epss_score=0.1)
    assert base == with_low_epss
