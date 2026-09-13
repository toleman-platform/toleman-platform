"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, GitHubAppInstallation } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Github, CheckCircle2, XCircle, Trash2, AlertTriangle } from "lucide-react";

type GithubAppStatus = {
  apps: GitHubAppInstallation[];
  app_configured: boolean;
  app_slug: string | null;
  installed: boolean;
  account_login: string | null;
  webhook_secret_set: boolean;
  // (#355) Not about any App in `apps` -- about the one being created.
  // False means GitHub will reject the manifest outright, so "Connect
  // GitHub" cannot succeed until PUBLIC_API_URL (echoed as
  // public_api_url) is publicly reachable.
  webhook_reachable: boolean;
  public_api_url: string;
};

export function ConnectGithubCard() {
  const router = useRouter();
  const [status, setStatus] = useState<GithubAppStatus | null>(null);
  const [org, setOrg] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [webhookSecrets, setWebhookSecrets] = useState<Record<number, string>>({});
  const [savingSecretFor, setSavingSecretFor] = useState<number | null>(null);
  // Deleting a registered App drops its private key/client secret and every
  // installation row under it -- same destructive-confirmation pattern as
  // workspace-roles.tsx's role removal, not a bare button with no warning.
  const [pendingDelete, setPendingDelete] = useState<GitHubAppInstallation | null>(null);
  const [deleting, setDeleting] = useState(false);

  function refresh() {
    api
      .githubAppStatus()
      .then(setStatus)
      .catch((e) => {
        // A failed status read used to just leave the skeleton up. Now that
        // the connect action is gated on this response (#355), a silent
        // failure reads as "the button is broken" with nothing to act on.
        setError(e instanceof Error ? e.message : "failed to load GitHub App status");
      });
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.deleteGithubApp(pendingDelete.id);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete GitHub App");
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  }

  useEffect(refresh, []);

  // (#355) Whether GitHub will accept a manifest built from this
  // deployment's PUBLIC_API_URL at all. Read from /status, which loads
  // whether or not an App exists yet; it used to come from a second
  // /manifest-data call on mount, which both minted a throwaway CSRF state
  // token per page load and only ever fed a warning rendered next to
  // already-created Apps. Null while status is still loading, and the
  // connect action stays disabled until we know, since the whole point is
  // not to start a flow that cannot finish.
  const webhookReachable = status === null ? null : status.webhook_reachable;

  async function connect() {
    setConnecting(true);
    setError(null);
    try {
      const { manifest, post_url } = await api.githubAppManifestData(org || undefined);
      // Built and submitted imperatively (not via React state -> JSX -> ref) so
      // there's no render-timing race between setting the value and submitting.
      const form = document.createElement("form");
      form.action = post_url;
      form.method = "post";
      form.style.display = "none";
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "manifest";
      input.value = JSON.stringify(manifest);
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to start GitHub connect flow");
      setConnecting(false);
    }
  }

  async function sync() {
    setSyncing(true);
    setSyncResult(null);
    try {
      const res = await api.githubAppSync();
      setSyncResult(`${res.created} new repo(s) added as targets`);
      router.refresh();
    } catch (e) {
      setSyncResult(e instanceof Error ? e.message : "sync failed");
    } finally {
      setSyncing(false);
    }
  }

  async function saveWebhookSecret(configId: number) {
    const value = (webhookSecrets[configId] || "").trim();
    if (!value) return;
    setSavingSecretFor(configId);
    try {
      await api.updateWebhookSecret(value, configId);
      setWebhookSecrets((prev) => ({ ...prev, [configId]: "" }));
      refresh();
    } finally {
      setSavingSecretFor(null);
    }
  }

  return (
    <>
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
            <Github className="h-5 w-5" />
          </div>
          <div>
            <div className="font-medium text-foreground">GitHub</div>
            <div className="text-xs text-muted-foreground">
              Install one or more Toleman GitHub Apps to sync and auto-discover repos
            </div>
          </div>
        </div>

        {status === null && (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-9 w-40" />
          </div>
        )}

        {status && status.apps.length > 0 && (
          <div className="flex flex-col gap-3">
            {status.apps.map((appEntry) => (
              <div key={appEntry.id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between">
                  <div className="text-sm font-medium text-foreground">
                    <code>{appEntry.app_slug}</code>
                  </div>
                  <div className="flex items-center gap-2">
                    <a href={safeHref(`https://github.com/apps/${appEntry.app_slug}/installations/new`)} target="_blank" rel="noreferrer">
                      <Button size="sm" variant="outline">
                        Add installation
                      </Button>
                    </a>
                    {/* GitHub Apps have no API to change permissions or
                        webhook event subscriptions -- only the App's own
                        settings page can. A "Manage on GitHub" link is the
                        honest affordance here; an in-app edit form would
                        imply Toleman can do this itself, which it can't.
                        manage_url is server-computed (org- vs personal-owned
                        Apps live under different URL shapes; guessing 404s). */}
                    <Button asChild size="sm" variant="outline">
                      <a href={safeHref(appEntry.manage_url)} target="_blank" rel="noreferrer">
                        Manage on GitHub
                      </a>
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-destructive hover:text-destructive"
                      onClick={() => setPendingDelete(appEntry)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                {appEntry.installations.length === 0 ? (
                  <p className="mt-1 text-xs text-muted-foreground">
                    App created but not installed on any account/org yet.
                  </p>
                ) : (
                  <div className="mt-1 flex flex-col gap-1">
                    {appEntry.installations.map((inst) => (
                      <div key={inst.installation_id} className="flex items-center gap-2 text-xs text-chart-5">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        <span className="text-muted-foreground">
                          Connected as {inst.account_login} ({inst.account_type})
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="mt-2 flex flex-col gap-2 border-t border-border pt-2">
                  <div className="flex items-center gap-2 text-xs">
                    {appEntry.webhook_secret_set ? (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5 text-chart-5" />
                        <span className="text-muted-foreground">
                          Webhook secret set, real-time PR scanning active if this App&apos;s webhook is configured
                        </span>
                      </>
                    ) : (
                      <>
                        <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="text-muted-foreground">
                          No webhook secret set, PRs from this App only scan on-demand (PR History page)
                        </span>
                      </>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <Input
                      type="password"
                      className="bg-secondary"
                      placeholder="Webhook secret (must match this App's GitHub settings)"
                      value={webhookSecrets[appEntry.id] || ""}
                      onChange={(e) => setWebhookSecrets((prev) => ({ ...prev, [appEntry.id]: e.target.value }))}
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => saveWebhookSecret(appEntry.id)}
                      disabled={savingSecretFor === appEntry.id || !(webhookSecrets[appEntry.id] || "").trim()}
                      className="shrink-0"
                    >
                      {savingSecretFor === appEntry.id ? "Saving..." : "Save"}
                    </Button>
                  </div>
                </div>
              </div>
            ))}

            <Button onClick={sync} disabled={syncing} variant="outline" className="self-start">
              {syncing ? "Syncing..." : "Sync Repos Now"}
            </Button>
            {syncResult && <p className="text-xs text-muted-foreground">{syncResult}</p>}
          </div>
        )}

        <div className="flex flex-col gap-2 border-t border-border pt-3">
          {/* (#355) Rendered before the create action, not next to existing
              Apps, because the only install this can happen on is one with
              no Apps at all: a default local install, where the operator
              previously got no warning here and GitHub's rejection page
              instead. The button below is disabled on the same condition,
              so the failure is caught here rather than on github.com. */}
          {status && !status.webhook_reachable && (
            <div className="flex gap-2 rounded-md border border-border bg-secondary p-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
              <div className="flex flex-col gap-2 text-xs text-muted-foreground">
                <p className="font-medium text-foreground">
                  GitHub will reject a new App while <code>PUBLIC_API_URL</code> is a localhost address.
                </p>
                <p>
                  <code>PUBLIC_API_URL</code> is <code>{status.public_api_url}</code>. The App manifest declares
                  that host as its webhook URL, and GitHub validates it at submission, refusing any address it
                  cannot reach over the public internet (&quot;Hook url is not supported because it isn&apos;t
                  reachable over the public Internet&quot;). Nothing is created, so this is not a working App
                  minus automatic scanning; it is no App and no integration at all.
                </p>
                <p>
                  Set <code>PUBLIC_API_URL</code> to a publicly reachable URL, then restart the{" "}
                  <code>backend</code> and <code>celery-worker</code> services to pick it up. For local work a
                  tunnel is the usual answer, and <code>cloudflared tunnel --url http://localhost:8000</code>{" "}
                  needs no account.
                </p>
                <p>
                  There is no API to change an App&apos;s webhook URL after it is created, only its GitHub
                  settings page by hand, so a throwaway tunnel URL has to be re-entered there every time the
                  tunnel restarts. A named tunnel or a real domain is the better default for anything past one
                  test.
                </p>
                <p>
                  <code>PUBLIC_BASE_URL</code> can stay on localhost for a solo local setup: GitHub only
                  validates the webhook URL, and the App&apos;s redirect URL is followed by your own browser.
                  The cost is that every link Toleman posts into a pull request points at a host only this
                  machine can reach.
                </p>
              </div>
            </div>
          )}
          <p className="text-xs text-muted-foreground">
            {status && status.apps.length > 0
              ? "Register another GitHub App (e.g. a separate dev/prod App, or one scoped to a different org):"
              : "Leave blank to install on your personal account, or enter an org name to install there instead."}
          </p>
          <div className="flex gap-2">
            <Input
              className="bg-secondary"
              placeholder="Organization (optional)"
              value={org}
              onChange={(e) => setOrg(e.target.value)}
            />
            <Button onClick={connect} disabled={connecting || webhookReachable !== true} className="shrink-0">
              {connecting ? "Redirecting..." : "Connect GitHub"}
            </Button>
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
        </div>
      </CardContent>
    </Card>

    <ConfirmDialog
      open={pendingDelete !== null}
      title="Delete GitHub App"
      description={
        pendingDelete ? (
          <>
            Delete <span className="font-medium text-foreground">{pendingDelete.app_slug}</span> and every
            installation under it? This only removes Toleman&apos;s record of the App -- it stays installed on
            GitHub&apos;s side until removed from GitHub&apos;s own settings. Repos already synced from it are
            not removed.
          </>
        ) : null
      }
      confirmLabel="Delete"
      tone="destructive"
      loading={deleting}
      onConfirm={confirmDelete}
      onCancel={() => setPendingDelete(null)}
    />
    </>
  );
}
