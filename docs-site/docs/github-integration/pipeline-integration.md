---
sidebar_position: 3
---

# CI/CD Pipeline Integration

Rikugan can open a real PR against a target repo that adds a GitHub Actions workflow running Semgrep/Gitleaks/Trivy (+ gosec, if Go is detected) natively and pushing results back to Rikugan.

## Per-target integration

`GET /api/targets/{id}/pipeline-workflow` generates the workflow YAML for preview. `POST /api/targets/{id}/pipeline-integrate` opens a real PR adding it, via the GitHub App installation token — same token-minting path PR Guardrail uses to set commit statuses.

The generated workflow requires two repo secrets, pointing at a **publicly reachable** Rikugan deployment (a `localhost` backend can't be reached by GitHub's cloud runners):

- `RIKUGAN_API_URL`
- `RIKUGAN_API_KEY` — the target's workspace API key

Results are pushed via `POST /api/ingest/{target_id}` (SARIF), authenticated by that key rather than a session cookie.

## Bulk integration

Select multiple targets in the Targets page (or `POST /api/targets/bulk-pipeline-integrate` with a list of `target_ids`) to roll pipeline integration out across many repos at once. This:

- Drops any target you can't access or don't hold at least `DEVELOPER` on
- Creates one tracking batch + one item per eligible target
- Processes items **sequentially** with a small delay between them, to stay polite to GitHub's rate limits (not full rate-limit-aware concurrency yet)
- Skips targets that are already integrated, reporting them `already_integrated` rather than re-running or failing them

Poll `GET /api/targets/bulk-pipeline-integrate/{batch_id}` for live per-repo status (succeeded / failed / already_integrated per item — one repo's GitHub error never sinks the whole batch).

## Mass rollout

`POST /api/targets/mass-pipeline-rollout` is the org-wide version — roll pipeline integration out across every target in scope in one call, same per-item outcome tracking as bulk integration.

## Permissions

Opening a PR that adds `.github/workflows/*` requires the GitHub App's separate **workflows** permission (distinct from `contents`). See [Connecting GitHub](./connecting-github.md) for what to do if you get a 403 here on an older App install.
