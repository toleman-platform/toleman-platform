---
sidebar_position: 2
---

# API Discovery & Active Scanning

## Discovery (static)

`POST /api/discovery` extracts API routes from a target's source via regex-based analysis (`backend/app/scanners/discovery.py`) — no live traffic involved. Results persist per-target and roll up into an org-wide aggregate view.

## Active scanning (dynamic)

Once routes are discovered, you can actively probe them with **nuclei**:

```bash
POST /api/api-scan/{target_id}
```

This only works against endpoints Rikugan already discovered for a target **whose owner already configured a host** — `Target.api_base_url` (set via `PATCH /api/targets/{id}`) is the *only* source of a scan host. Any discovered route that would resolve outside that host's netloc is dropped, not scanned — a caller can never point an active scan at an arbitrary third-party URL.

Safety defaults:
- Excludes `dos`, `fuzz`, `intrusive` nuclei template tags by default — a first run is passive/safe
- Both nuclei's own rate-limit/timeout flags and the subprocess call itself are bounded

Results are ordinary `Finding` rows tagged `tool="api-scan"` — **not** a separate schema, so dedup, priority scoring, SLA, Jira auto-create, and notifications all apply unmodified. Read the latest run: `GET /api/api-scan/{target_id}/latest`.
