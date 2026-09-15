"""A nuclei timeout must say enough to act on (#493).

Active API scanning failed in production with exactly this, and nothing
else: "nuclei scan timed out after retries". That sentence does not say how
many endpoints were in the run, how long nuclei was given, or whether it
had produced anything before being killed -- which are the facts that
separate the two causes needing opposite responses:

  * a slow or unreachable host, where every request burns its own timeout
    and nuclei produces nothing (raising the budget changes nothing);
  * a run that is working and simply needs longer than the budget.

The budget itself was also the wrong shape: a flat 300s gave a 5-endpoint
target and a 500-endpoint target the same allowance, and since
nuclei_rate_limit caps requests per second, the large one could not finish
within it on any attempt. All three retries then failed identically.
"""
import subprocess

from app.core.config import settings
from app.tasks.api_scan_tasks import (
    NUCLEI_TIMEOUT_CEILING_SECONDS,
    describe_nuclei_timeout,
    nuclei_timeout_for,
)


def _timeout(stdout, seconds=300):
    return subprocess.TimeoutExpired(cmd=["nuclei"], timeout=seconds, output=stdout)


def test_budget_scales_with_endpoint_count():
    small = nuclei_timeout_for(5)
    large = nuclei_timeout_for(200)

    assert large > small, "a 200-endpoint target cannot share a 5-endpoint target's budget"


def test_budget_never_drops_below_the_configured_floor():
    """A tiny target must not get a tiny budget: one slow endpoint can
    still take longer than its per-endpoint share."""
    assert nuclei_timeout_for(0) >= settings.nuclei_timeout_seconds
    assert nuclei_timeout_for(1) >= settings.nuclei_timeout_seconds


def test_budget_is_capped():
    """This runs on a Celery worker. An unbounded budget turns one
    unreachable target into a worker blocked indefinitely."""
    assert nuclei_timeout_for(100_000) == NUCLEI_TIMEOUT_CEILING_SECONDS


def test_a_timeout_with_no_output_points_at_an_unreachable_host():
    message = describe_nuclei_timeout(_timeout(""), url_count=40)

    assert "40 endpoint" in message
    assert "300" in message
    assert "unreachable" in message


def test_a_timeout_with_partial_output_reports_the_progress():
    """Distinguishes "working, needs longer" from "never got anywhere"."""
    stdout = '{"template-id": "a"}\n{"template-id": "b"}\n'
    message = describe_nuclei_timeout(_timeout(stdout), url_count=40)

    assert "2 finding" in message
    assert "making progress" in message


def test_a_truncated_final_line_does_not_break_the_diagnosis():
    """The killed process almost always leaves a half-written object as its
    last line; skipping it is the point, not a concession."""
    stdout = '{"template-id": "a"}\n{"template-id": "b"}\n{"template-i'
    message = describe_nuclei_timeout(_timeout(stdout), url_count=10)

    assert "2 finding" in message


def test_bytes_output_is_handled():
    """subprocess gives bytes unless text=True was in force; the diagnosis
    must not depend on which."""
    message = describe_nuclei_timeout(_timeout(b'{"template-id": "a"}\n'), url_count=3)

    assert "1 finding" in message
