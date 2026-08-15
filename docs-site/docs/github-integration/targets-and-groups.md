---
sidebar_position: 2
---

# Targets & Repo Groups

A **Target** is a repo Rikugan scans. Targets belong to a Workspace.

## Adding a target

```bash
POST /api/targets
{
  "workspace_id": 1,
  "name": "myrepo",
  "repo_url": "https://github.com/org/repo.git",
  "default_branch": "main",
  "label": "Dev",
  "criticality_weight": 2
}
```

Or use the **Targets** page in the UI, which drives the same endpoint. `criticality_weight` feeds priority scoring (see [Findings Lifecycle & Scoring](../findings/lifecycle-and-scoring.md)).

`PATCH /api/targets/{id}` updates a target — including `api_base_url`, which is the *only* source of a host for [Active API Scanning](../scanning/api-discovery-and-scanning.md); a nuclei scan can never be pointed at an arbitrary third-party URL.

## Groups & tags

Targets can be organized into **Groups** — `GET/POST/DELETE /api/targets/{id}/groups/{group_id}`. Groups let you set shared configuration (enforcement mode, SLA rules) that applies to every target in the group instead of per-repo. See [PR Guardrail](./pr-guardrail.md) for how group-level settings resolve.

## The "All repos" pattern

Wherever you see a repo dropdown (SBOM, Reports, Dashboard scoping), Rikugan uses one consistent pattern: a single dropdown with an "All repositories" entry at the top, not a separate tab or toggle. This is the `TargetPicker` component's `allowAll` prop, reused across every page that needs org-wide vs. per-repo scoping.

## Workspace API key

Each target's workspace has an API key (`GET /api/targets/{id}/workspace-key`, regenerate via `POST .../workspace-key/regenerate`) used to authenticate CI/CD pushes to the [ingest endpoint](./pipeline-integration.md) — this is separate from your session login and from the GitHub App token.
