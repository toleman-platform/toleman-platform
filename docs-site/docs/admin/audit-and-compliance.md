---
sidebar_position: 4
---

# Audit Log & Compliance Reports

## Audit log

`/api/audit` (login-scoped) records state changes across the platform — finding triage, role assignments, config changes. Combined with GitHub org activity in the **Activity Feed** (filterable, paginated, with bulk-triage grouping).

## Compliance reports

`/api/reports` exports your compliance posture as **CSV or PDF** — same downloadable-export pattern used by SBOM (`Content-Disposition: attachment`, fetched with credentials, downloaded as a blob). Scope to a single target, a group, or org-wide using the same "All repositories" `TargetPicker` pattern used throughout the app.
