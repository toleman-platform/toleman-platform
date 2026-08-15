---
sidebar_position: 1
---

# Dashboard & Security Score

## Configurable widget catalog

The dashboard is built from a small, concrete widget catalog (`app.core.widgets.WIDGET_CATALOG`) — deliberately not a generic arbitrary-chart-config system:

- `kpi_cards`
- `findings_trend`
- `cve_timeline`
- `sla_compliance`
- `top_risky_repos`
- `recent_findings`
- `security_score`

Each user has their own saved layout (`DashboardLayout` — ordered widget list). Edit mode lets you add/remove/reorder widgets (move-up-down buttons, not drag-and-drop). `GET /api/dashboard/widget-data` batches every widget's data in one round-trip; one widget's resolver failing shows an error just for that widget, not the whole dashboard.

## Security Score

`GET /api/dashboard/security-score` computes a 0–100 score + A–F letter grade from five real components:

1. **Open findings**, weighted by severity, normalized per in-scope target
2. **SLA compliance** (reuses the same logic as the SLA page — neutral 100 when no rule applies to any finding)
3. **Scan coverage** — % of targets with a scan in the last 30 days
4. **False-positive rate** — findings currently marked False Positive ÷ all findings ever, all-time
5. **Week-over-week trend** — reconstructed from the real `FindingStateLog` audit trail, not estimated

Scope to an org, a group, or a single target (`resolve_target_ids_for_scope`) — the standalone endpoint and the `security_score` dashboard widget always agree for the same scope, since they share this resolver.
