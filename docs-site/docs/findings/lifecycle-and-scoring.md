---
sidebar_position: 1
---

# Findings Lifecycle & Priority Scoring

## Lifecycle / states

A `Finding` moves through a triage state machine — states include (at minimum) **Open**, **Mitigated**, **Accepted Risk**, **False Positive**, **Won't Fix**, and **Reopened**. `Reopened` still counts as "open" for SLA-violation purposes. Every state change is recorded in `FindingStateLog`, a real audit trail (used e.g. by the Security Score's week-over-week trend).

Bulk triage is available on the Findings page (checkbox selection + bulk-action bar, reused by the Activity Feed's bulk-triage grouping).

## Deduplication

`compute_dedup_hash()` (`backend/app/core/dedup.py`) fingerprints a finding on `(rule_id, file_path, tool, normalized_snippet)`, so the same underlying issue survives line-shift refactors instead of re-appearing as a new finding. `file_path` must be normalized to be relative to the repo root (not the scan-scoped clone directory) before hashing — otherwise dedup silently breaks.

## Priority scoring

`backend/app/core/scoring.py` computes:

```
severity_weight × criticality_weight × 40
```

then boosts the score using real-time lookups:

- **EPSS** (Exploit Prediction Scoring System) — `core/epss.py`
- **CISA KEV** (Known Exploited Vulnerabilities) — `core/kev.py`, cached 1 hour

`criticality_weight` comes from the target's own configured criticality (set when adding/editing a target).
