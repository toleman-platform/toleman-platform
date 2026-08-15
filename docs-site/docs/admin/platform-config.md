---
sidebar_position: 3
---

# Platform Config

**Admin → Global Integrations** tab (`/api/config`, admin-only) holds every cross-cutting integration setting:

- **AI provider** — Anthropic or OpenAI-compatible endpoint + key, used by [AI Analysis](../findings/enrichment-and-ai-analysis.md)
- **Slack** — incoming webhook URL for notifications
- **Jira** — base URL, API token, project key, issue type, and an auto-create severity threshold

## Secrets at rest

Secret fields (GitHub App secrets, the OpenAI-compatible provider key, Slack webhook URL, Jira API token) are encrypted with Fernet (`encrypt_secret()`/`decrypt_secret()` in `core/crypto.py`, key from `PLATFORM_ENCRYPTION_KEY`) and never echoed back in plaintext — the API returns a `*_set: boolean` instead of the value once configured.

`PlatformConfig.anthropic_api_key` is a known pre-existing plaintext exception — not a pattern to copy for new secret fields.

## Testing a connection

`POST /api/config/test-slack` and `POST /api/config/test-jira` make **real outbound calls** to verify credentials — used by the "Test Connection" buttons next to each integration, not a mocked check.

## Auto-ticket creation

`jira_auto_create_severity` is a single severity threshold (e.g. "Critical" auto-creates a Jira ticket for Critical-or-above findings). It's checked once, right after a net-new finding is committed — best-effort: a Jira outage is logged, never raised, so it can't fail a scan. This is deliberately a single scalar rather than a full rule table (unlike Policy/SLA rules) — a natural next step if more granular criteria are needed later.
