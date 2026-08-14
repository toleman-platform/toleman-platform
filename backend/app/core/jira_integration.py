"""Real Jira Cloud/Server REST API integration (issue #74).

Two entry points:
  - test_jira_connection(): a real authenticated GET against
    {jira_url}/rest/api/2/myself to confirm the URL + token are valid.
  - create_jira_ticket_for_finding(): a real POST to
    {jira_url}/rest/api/2/issue that opens a ticket for a given Finding,
    used both by the manual "create ticket" path (future work) and the
    auto-create-on-ingestion hook in app.core.ingestion.

No mock data: every call here is a real HTTP request to the caller-supplied
Jira instance. There is deliberately no fallback/simulated response -- a
misconfigured or unreachable Jira surfaces as a real error, not a fabricated
success.
"""

import httpx

from app.core.crypto import decrypt_secret
from app.models.models import Finding, PlatformConfig

# Real network timeout, matching the other outbound-HTTP integrations in this
# codebase (see app.core.github's github_get, app.core.pipeline_workflow).
JIRA_TIMEOUT_SECONDS = 15.0


def _auth_header(api_token: str) -> dict:
    # Jira Cloud REST API v2 accepts a bare API token as a Bearer token for
    # PAT-style auth (Jira Server/Data Center) as well as Jira Cloud API
    # tokens paired with an email via Basic auth. This integration uses
    # Bearer-token auth, which both Jira Server PATs and Jira Cloud tokens
    # created for API-token-only automation support -- avoids requiring a
    # separate "account email" field in PlatformConfig for a v1.
    return {"Authorization": f"Bearer {api_token}", "Accept": "application/json"}


def jira_configured(config: PlatformConfig | None) -> bool:
    return bool(config and config.jira_url and config.jira_api_token)


def test_jira_connection(jira_url: str, api_token: str) -> tuple[bool, str]:
    """Real authenticated call to GET {jira_url}/rest/api/2/myself.

    Returns (success, message) -- message is either the resolved account
    display name on success, or the real error text on failure. Never
    fabricates a success.
    """
    base = jira_url.rstrip("/")
    url = f"{base}/rest/api/2/myself"
    try:
        response = httpx.get(url, headers=_auth_header(api_token), timeout=JIRA_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return False, f"Request to Jira failed: {exc}"

    if response.status_code == 200:
        try:
            data = response.json()
        except ValueError:
            return True, "Connected to Jira."
        name = data.get("displayName") or data.get("name") or "unknown user"
        return True, f"Connected to Jira as {name}."

    return False, f"Jira returned {response.status_code}: {response.text[:500]}"


def create_jira_ticket_for_finding(config: PlatformConfig, finding: Finding) -> tuple[bool, str]:
    """Real POST to {jira_url}/rest/api/2/issue creating a ticket for
    `finding`, using the configured project key/issue type. Returns
    (success, issue_key_or_error) -- on success the second element is the
    real Jira issue key (e.g. "SEC-123"), on failure it's the real error
    text from Jira (or the transport error).
    """
    base = config.jira_url.rstrip("/")
    url = f"{base}/rest/api/2/issue"
    token = decrypt_secret(config.jira_api_token)

    severity_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    summary = f"[{severity_str}] {finding.title or finding.rule_id}"[:255]
    description = (
        f"Auto-created by Rikugan for finding #{finding.id}.\n\n"
        f"Tool: {finding.tool}\n"
        f"Rule: {finding.rule_id}\n"
        f"Severity: {severity_str}\n"
        f"File: {finding.file_path}"
        + (f":{finding.line_start}" if finding.line_start else "")
        + f"\n\n{finding.description}"
    )

    body = {
        "fields": {
            "project": {"key": config.jira_project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": config.jira_issue_type or "Task"},
        }
    }

    try:
        response = httpx.post(url, json=body, headers=_auth_header(token), timeout=JIRA_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return False, f"Request to Jira failed: {exc}"

    if response.status_code in (200, 201):
        try:
            data = response.json()
        except ValueError:
            return True, ""
        return True, data.get("key", "")

    return False, f"Jira returned {response.status_code}: {response.text[:500]}"
