---
sidebar_position: 3
---

# SLA Rules & Policy

## SLA rules

Unlike enforcement mode's single inherited value, an SLA is a **matrix** — `SlaRule` rows keyed by `(workspace_id, group_id | null, severity)`, each with a `days_to_fix`. Critical and Low findings need very different windows even within the same group.

Resolution order (`resolve_sla_days_with_source`):

1. A group the finding's target belongs to has a rule for this severity — most-restrictive (fewest days) wins on multi-group conflict
2. Else the workspace's default rule (`group_id = null`) for this severity
3. Else no SLA is shown (never a fabricated number)

There's deliberately no per-target SLA override — only workspace/group.

`GET /api/findings` and `/{id}` embed `sla_days`/`sla_violated` on every finding. A finding is only "in violation" while it's still open (states other than Mitigated/Accepted Risk/False Positive/Won't Fix — Reopened still counts as open). `GET /api/dashboard/sla-compliance` aggregates workspace-wide.

Manage rules: **Admin → SLA Rules** tab, or `/api/sla-rules` (SECURITY_ENGINEER-or-admin for writes).

## Policy-as-code

`/api/policies` (admin) defines which finding severities/types count as **blocking** for PR Guardrail. This is a distinct axis from [enforcement mode](../github-integration/pr-guardrail.md#enforcement-modes): policy decides *what's* blocking; enforcement mode decides whether a PR carrying blocking findings actually fails the build.
