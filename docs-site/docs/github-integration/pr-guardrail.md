---
sidebar_position: 4
---

# PR Guardrail

PR Guardrail scans a pull request's diff for **net-new** findings only, and can block or warn on the PR via a GitHub commit status.

## Running a scan

`POST /api/pr-guardrail/scan` runs a diff scan against a PR. Findings land in `PRGuardrailFinding` — a table kept separate from the main `Finding` table so PR-branch noise never pollutes your default-branch security posture. `GET /api/pr-guardrail/log` lists past scans; `GET /api/pr-guardrail/{pr_scan_id}/findings` lists one scan's findings.

## Enforcement modes

Every target, group, and workspace has an `enforcement_mode`: `block`, `alert`, or `disabled`. Resolution is **most-specific-wins**:

1. The target's own value, if set
2. Else its group's value (a target in multiple disagreeing groups resolves to the **most restrictive** — `block` > `alert` > `disabled`, fail-closed)
3. Else the workspace's value
4. Else the hardcoded default, `block`

- **block**: blocking findings fail the GitHub commit status (build fails)
- **alert**: the PR comment still posts, but the commit status reports `success` with a note that it's non-blocking (GitHub commit statuses have no "neutral" state)
- **disabled**: PR Guardrail doesn't run at all — checked before any clone/scan/comment/status

This is a distinct concept from **Policy** (below): policy decides *which* findings are severe enough to count as blocking; enforcement mode decides whether a PR carrying blocking findings actually fails the build.

## Accept risk / ignore workflow

A developer can request an ignore on a specific finding (`POST /api/pr-guardrail/findings/{id}/request-ignore`). A reviewer with the right role approves (`.../approve-ignore`) or rejects (`.../reject-ignore`) it. Pending requests across the workspace: `GET /api/pr-guardrail/ignore-requests/pending`.

An admin/security engineer can also override a whole PR's status directly: `POST /api/pr-guardrail/{pr_scan_id}/override`.

## Policy-as-code

`policies` (`/api/policies`, admin) lets you define rules for which finding severities/types count as PR-blocking, independent of enforcement mode.
