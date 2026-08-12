from app.models.models import Severity, SEVERITY_WEIGHT


def compute_priority_score(
    severity: Severity,
    target_criticality_weight: int,
    epss_score: float | None = None,
    kev_listed: bool = False,
) -> int:
    """
    Base: Severity Weight (1-5) * Target Criticality Weight (1-5) * 40  -> max 1000.

    Exploitability modifier (closes the "true risk" gap flagged in architecture review):
      - KEV-listed (known exploited in the wild) -> floor of 900.
      - EPSS > 0.5 (high real-world exploit probability) -> bump one severity tier's worth.
    """
    weight = SEVERITY_WEIGHT[severity]
    base = weight * max(1, min(5, target_criticality_weight)) * 40
    score = min(1000, base)

    if kev_listed:
        score = max(score, 900)
    elif epss_score is not None and epss_score > 0.5:
        score = min(1000, score + 160)  # roughly one severity tier at mid criticality

    return score
