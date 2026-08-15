"""SIEM export (issue #114): a generic outbound webhook -- one JSON POST per
qualifying finding, the same shape virtually every SIEM/log pipeline can
ingest directly (Splunk HTTP Event Collector, Elastic/Datadog generic
webhook input) or relay through a small middleware. Deliberately not one
specific vendor's proprietary wire format for this first version -- see
PlatformConfig.siem_webhook_url's docstring for why.

Same "shared low-level sender + test function call it" shape as
app.core.slack_integration, and same "no mock data" rule: test_siem_webhook
always makes a real HTTP call and reports the real response.
"""
import httpx

from app.models.models import Finding, Target

SIEM_TIMEOUT_SECONDS = 15.0


def finding_to_siem_event(finding: Finding, target: Target) -> dict:
    """The exported event shape. Flat, generic field names (not CEF/LEEF
    syntax) so a receiving webhook/Splunk HEC/Elastic ingest pipeline can
    map fields without needing to parse a specialized encoding first."""
    return {
        "source": "rikugan",
        "event_type": "finding",
        "finding_id": finding.id,
        "dedup_hash": finding.dedup_hash,
        "severity": finding.severity,
        "priority_score": finding.priority_score,
        "state": finding.state,
        "title": finding.title,
        "description": finding.description,
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "cve_id": finding.cve_id,
        "epss_score": finding.epss_score,
        "kev_listed": finding.kev_listed,
        "target_id": target.id,
        "target_name": target.name,
        "repo_url": target.repo_url,
        "branch": finding.branch,
        "first_seen": finding.first_seen.isoformat() + "Z",
    }


def send_finding_to_siem(webhook_url: str, finding: Finding, target: Target) -> tuple[bool, str]:
    """POST a real finding event to `webhook_url`. Returns (success, message)."""
    try:
        response = httpx.post(webhook_url, json=finding_to_siem_event(finding, target), timeout=SIEM_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return False, f"Request to SIEM webhook failed: {exc}"

    if 200 <= response.status_code < 300:
        return True, response.text or "ok"

    return False, f"SIEM webhook returned {response.status_code}: {response.text[:500]}"


def test_siem_webhook(webhook_url: str) -> tuple[bool, str]:
    """POST a real test event to `webhook_url`. Returns (success, message)
    -- message is the real HTTP response either way."""
    test_event = {
        "source": "rikugan",
        "event_type": "test_connection",
        "message": "Rikugan test connection: this SIEM webhook is configured correctly.",
    }
    try:
        response = httpx.post(webhook_url, json=test_event, timeout=SIEM_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return False, f"Request to SIEM webhook failed: {exc}"

    if 200 <= response.status_code < 300:
        return True, response.text or "ok"

    return False, f"SIEM webhook returned {response.status_code}: {response.text[:500]}"
