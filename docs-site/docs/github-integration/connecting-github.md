---
sidebar_position: 1
---

# Connecting GitHub

Rikugan connects to GitHub via a **GitHub App** (not a PAT) for org-wide activity, PR Guardrail commit statuses, and pipeline-integration PRs.

## Create the App (manifest flow)

1. In Rikugan, go to **Settings → GitHub** and click **Connect GitHub**.
2. This calls `GET /api/github-app/manifest-data`, which builds a GitHub App manifest (name, webhook URL, required permissions — including `workflows: write`, needed for pipeline-integration PRs that add `.github/workflows/` files).
3. You're redirected to GitHub's manifest-flow page, where you approve and create the App against your org or personal account.
4. GitHub redirects back with a temporary code; Rikugan exchanges it for the App's credentials automatically.

## Multiple Apps / installations

Rikugan supports more than one `GitHubAppConfig` (e.g. separate Apps per GitHub org), each with its own set of `GitHubInstallation` rows. `GET /api/github-app/status` reports connection state per App/installation. The **Connect GitHub** card in Settings renders one section per configured App.

## Re-approving permissions

GitHub gates writes under `.github/workflows/` behind a separate **workflows** App permission, distinct from `contents`. If your App was installed before pipeline integration existed, its owner needs to re-approve the updated permission set from GitHub's App settings UI — this can't be automated from Rikugan's side. You'll see a `403 Resource not accessible by integration` on pipeline-integrate calls until that's done.

## Webhook secret

`PATCH /api/github-app/webhook-secret` lets an admin rotate the webhook signing secret without recreating the App. Webhook deliveries land on `POST /api/webhooks/github` and are verified by HMAC signature, not session auth.

## Syncing installations

`POST /api/github-app/sync` re-pulls the current installation list from GitHub (repos added/removed from the App outside of Rikugan).
