"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, GitHubAppInstallation } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Github, CheckCircle2, XCircle } from "lucide-react";

type GithubAppStatus = {
  apps: GitHubAppInstallation[];
  app_configured: boolean;
  app_slug: string | null;
  installed: boolean;
  account_login: string | null;
  webhook_secret_set: boolean;
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

  function refresh() {
    api.githubAppStatus().then(setStatus);
  }

  useEffect(refresh, []);

  // (GH-03) Whether GitHub could actually reach this backend's webhook
  // endpoint. The App now subscribes to pull_request, so automatic scanning
  // works -- unless PUBLIC_API_URL is a localhost address, in which case
  // deliveries never arrive and it looks exactly like a scanner finding
  // nothing. Better said before the App is created than discovered after.
  const [webhookReachable, setWebhookReachable] = useState<boolean | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .githubAppManifestData()
      .then((d) => {
        if (!cancelled) setWebhookReachable(d.webhook_reachable);
      })
      .catch(() => {
        // Advisory only -- never block the connect flow on it.
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
            <Github className="h-5 w-5" />
          </div>
          <div>
            <div className="font-medium text-foreground">GitHub</div>
            <div className="text-xs text-muted-foreground">
              Install one or more Rikugan GitHub Apps to sync and auto-discover repos
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
                  <a href={`https://github.com/apps/${appEntry.app_slug}/installations/new`} target="_blank" rel="noreferrer">
                    <Button size="sm" variant="outline">
                      Add installation
                    </Button>
                  </a>
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
                          Webhook secret set — real-time PR scanning active if this App&apos;s webhook is configured
                        </span>
                      </>
                    ) : (
                      <>
                        <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="text-muted-foreground">
                          No webhook secret set — PRs from this App only scan on-demand (PR History page)
                        </span>
                      </>
                    )}
                  </div>
                  {webhookReachable === false && (
                    <p className="text-xs text-muted-foreground">
                      PUBLIC_API_URL is a localhost address, so GitHub cannot deliver webhooks here and PRs will
                      only scan on demand. Set it to a publicly reachable URL (a domain or tunnel) for automatic
                      PR scanning. Note that a required status check nothing triggers will block every PR.
                    </p>
                  )}
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
            <Button onClick={connect} disabled={connecting} className="shrink-0">
              {connecting ? "Redirecting..." : "Connect GitHub"}
            </Button>
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
        </div>
      </CardContent>
    </Card>
  );
}
