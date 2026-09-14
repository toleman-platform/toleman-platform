"use client";

import { useState } from "react";
import { Copy, Eye, EyeOff, RotateCw } from "lucide-react";
import { api } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ui/error-state";

const MASKED_KEY = "•".repeat(32);

// Issue #224: workspace-id-keyed twin of settings/page.tsx's
// WorkspaceKeyCard, which took a `targetId` and proxied through
// api.workspaceKey(targetId), the only way to see a workspace's key was
// to first pick one of its targets in an unrelated target picker. This
// looks the key up directly by workspace id (api.workspaceApiKey), for the
// new Workspaces page where a workspace is what's actually selected.
export function WorkspaceKeyCard({ workspaceId }: { workspaceId: number }) {
  // Remounted with `key={workspaceId}` by the parent on workspace switch,
  // so per-workspace UI state resets for free (see the settings.tsx
  // original for the same pattern).
  //
  // The read used to be an uncaught `.then(setApiKey)` paired with
  // `if (!apiKey) return null`, so a slow or failed key read made this whole
  // card silently disappear -- and an operator who cannot see an API-key card
  // concludes the workspace has no key. Loading and failure are now each
  // rendered as themselves.
  const keyState = useAsyncData(() => api.workspaceApiKey(workspaceId), { deps: [workspaceId] });
  // A regenerate returns the new key once and once only, so it is held here
  // rather than re-read. Safe to keep outside the fetch state because the
  // parent remounts this card with `key={workspaceId}` on a workspace switch,
  // so one workspace's key can never survive into another's heading.
  const [regeneratedKey, setRegeneratedKey] = useState<string | null>(null);
  const apiKey = regeneratedKey ?? keyState.data?.api_key ?? null;

  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // `navigator.clipboard` is undefined on a non-secure origin (plain http over
  // a LAN is a normal self-hosted deployment), where this threw unhandled.
  async function copyKey() {
    if (!apiKey) return;
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopyFailed(false);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyFailed(true);
      setRevealed(true);
    }
  }

  async function regenerate() {
    setRegenerating(true);
    setError(null);
    try {
      const r = await api.regenerateWorkspaceApiKey(workspaceId);
      setRegeneratedKey(r.api_key);
      setRevealed(true);
      setConfirming(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to regenerate key");
    } finally {
      setRegenerating(false);
    }
  }

  if (keyState.isInitialLoading) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-3 px-4 py-4" aria-busy="true">
          <Skeleton className="h-3 w-72" />
          <Skeleton className="h-9 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (apiKey === null) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="px-4 py-4">
          <ErrorState
            title="Couldn't load this workspace's API key"
            description={keyState.error?.message ?? "The key could not be read. It has not been changed."}
            action={
              <Button size="sm" variant="outline" onClick={keyState.refetch}>
                Try again
              </Button>
            }
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-3 px-4 py-4">
        <div>
          <p className="text-xs text-muted-foreground">Workspace API key (for CI push ingestion, X-API-Key header)</p>
          <p className="text-xs text-muted-foreground">
            This key authenticates automated pipeline pushes to this workspace. Anyone holding it can push findings
            on your behalf.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <code className="flex-1 break-all rounded-md bg-secondary px-3 py-2 text-sm text-foreground">
            {revealed ? apiKey : MASKED_KEY}
          </code>
          <Button
            variant="outline"
            size="icon"
            aria-label={revealed ? "Hide API key" : "Reveal API key"}
            title={revealed ? "Hide API key" : "Reveal API key"}
            onClick={() => setRevealed((v) => !v)}
          >
            {revealed ? <EyeOff /> : <Eye />}
          </Button>
          <Button variant="outline" size="icon" aria-label="Copy API key" title="Copy API key" onClick={copyKey}>
            <Copy />
          </Button>
        </div>
        {copied && (
          <span role="status" className="text-xs text-chart-5">
            Copied to clipboard
          </span>
        )}
        {copyFailed && (
          <span role="alert" className="text-xs text-destructive">
            Couldn&apos;t write to the clipboard (this browser blocks it outside a secure origin). The key is revealed
            above &mdash; select and copy it manually.
          </span>
        )}

        <div className="flex flex-col gap-2 border-t border-border pt-3">
          {!confirming ? (
            <Button
              variant="outline"
              size="sm"
              className="self-start text-destructive hover:text-destructive"
              onClick={() => setConfirming(true)}
            >
              <RotateCw />
              Regenerate key
            </Button>
          ) : (
            <div className="flex flex-col gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3">
              <p className="text-xs text-foreground">
                Regenerating invalidates the current key <strong>immediately</strong>. Any CI pipeline still using it
                will start failing to push findings until it&apos;s updated with the new key. This can&apos;t be
                undone.
              </p>
              <div className="flex items-center gap-2">
                <Button variant="destructive" size="sm" disabled={regenerating} onClick={regenerate}>
                  {regenerating ? "Regenerating…" : "Yes, regenerate now"}
                </Button>
                <Button variant="outline" size="sm" disabled={regenerating} onClick={() => setConfirming(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
          {error && (
            <p role="alert" className="text-xs text-destructive">
              {error}
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
