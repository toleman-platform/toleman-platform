---
sidebar_position: 2
---

# Enrichment & AI Analysis

Rikugan has two, deliberately separate ways to add context to a finding.

## No-AI enrichment (works with zero AI provider configured)

`GET /api/findings/{id}/enrichment` returns real CVE description, CVSS, and CWE data — fetched live from:

- **NVD** (`core/nvd.py`)
- **OSV.dev** (`core/osv.py`) — queried directly by CVE ID, which OSV resolves as an alias, for known-fixed versions

Both are free, no API key required. Results are cached **forever** in the `CveEnrichment` table (unlike EPSS/KEV's short-TTL cache) — a single CVE's published data is effectively immutable. Findings with no `cve_id` (SAST/secrets findings) get null fields rather than a fabricated CWE/CVSS.

## AI Analysis

A separate feature (`/api/ai`) that calls a configured AI provider — **Anthropic or an OpenAI-compatible endpoint** (set in **Settings → Platform Config**) — for remediation guidance on a specific finding. Entry point: search or browse recent analyses from the **AI Analysis** page.

This is opt-in and requires a provider key configured by an admin; no-AI enrichment above works without it.
