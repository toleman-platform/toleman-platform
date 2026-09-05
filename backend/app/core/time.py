from datetime import UTC, datetime


def utcnow() -> datetime:
    """Naive UTC timestamp, matching the semantics of the deprecated
    ``datetime.utcnow`` so values stay interchangeable with the naive
    ``datetime`` columns used throughout the schema."""
    return datetime.now(UTC).replace(tzinfo=None)
