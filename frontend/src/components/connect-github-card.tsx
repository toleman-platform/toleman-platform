"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Github, CheckCircle2 } from "lucide-react";

export function ConnectGithubCard() {
  const router = useRouter();
  const [status, setStatus] = useState<{
    app_configured: boolean;
    app_slug: string | null;
    installed: boolean;
    account_login: string | null;
  } | null>(null);
  const [org, setOrg] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    api.githubAppStatus().then(setStatus);
  }

  useEffect(refresh, []);

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

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Github className="h-5 w-5" />
          </div>
          <div>
            <div className="font-medium text-foreground">GitHub</div>
            <div className="text-xs text-muted-foreground">
              Install the OSP GitHub App to sync and auto-discover repos
            </div>
          </div>
        </div>

        {status === null && <p className="text-sm text-muted-foreground">Checking status...</p>}

        {status && !status.app_configured && (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted-foreground">
              Leave blank to install on your personal account, or enter an org name to install there instead.
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
        )}

        {status && status.app_configured && !status.installed && (
          <div className="flex flex-col gap-2">
            <p className="text-sm text-muted-foreground">
              App <code className="text-foreground">{status.app_slug}</code> was created. Finish installing it on
              your account or org:
            </p>
            <a href={`https://github.com/apps/${status.app_slug}/installations/new`} target="_blank" rel="noreferrer">
              <Button>Install App</Button>
            </a>
          </div>
        )}

        {status && status.installed && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-sm text-chart-5">
              <CheckCircle2 className="h-4 w-4" />
              Connected as {status.account_login}
            </div>
            <Button onClick={sync} disabled={syncing} variant="outline" className="self-start">
              {syncing ? "Syncing..." : "Sync Repos Now"}
            </Button>
            {syncResult && <p className="text-xs text-muted-foreground">{syncResult}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
