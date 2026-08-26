"""Real Slack incoming-webhook integration (issue #74).

Slack's incoming-webhook contract (https://api.slack.com/messaging/webhooks)
is a plain POST of a JSON payload (at minimum {"text": "..."}) to the
per-workspace webhook URL configured in PlatformConfig. A successful call
returns HTTP 200 with the literal body "ok"; failures return a 4xx/5xx with a
short plaintext error (e.g. "invalid_payload", "channel_not_found").

No mock data: test_slack_webhook() always makes a real HTTP call to the
caller-supplied URL and reports the real response -- there is no simulated
success path.
"""

import httpx

SLACK_TIMEOUT_SECONDS = 15.0


def send_slack_message(webhook_url: str, text: str) -> tuple[bool, str]:
    """POST a real message to `webhook_url`. Returns (success, message) --
    message is Slack's real response body either way. This is the shared
    low-level sender: test_slack_webhook() (below) and
    app.core.notifications.dispatch_notification (issue #73's real
    notification dispatch) both call this instead of each making their own
    HTTP request, so there is exactly one place that knows Slack's incoming-
    webhook contract."""
    try:
        response = httpx.post(webhook_url, json={"text": text}, timeout=SLACK_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return False, f"Request to Slack failed: {exc}"

    if response.status_code == 200:
        return True, response.text or "ok"

    return False, f"Slack returned {response.status_code}: {response.text[:500]}"


def test_slack_webhook(webhook_url: str, text: str = "Toleman test connection: this webhook is configured correctly.") -> tuple[bool, str]:
    """POST a real test message to `webhook_url`. Returns (success, message)
    -- message is Slack's real response body either way."""
    return send_slack_message(webhook_url, text)
