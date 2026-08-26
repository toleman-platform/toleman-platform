"use client";

import { useEffect, useState } from "react";
import { Copy, Eye, EyeOff, RotateCw } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const MASKED_KEY = "•".repeat(32);

// Issue #224: workspace-id-keyed twin of settings/page.tsx's
// WorkspaceKeyCard, which took a `targetId` and proxied through
// api.workspaceKey(targetId), the only way to see a workspace's key was
// to first pick one of its targets in an unrelated target picker. This
// looks the key up directly by workspace id (api.workspaceApiKey), for the
// new Workspaces page where a workspace is what's actually selected.
export function WorkspaceKeyCard({ workspaceId }: { workspaceId: number }) {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Remounted with `key={workspaceId}` by the parent on workspace switch,
  // so per-workspace UI state resets for free (see the settings.tsx
  // original for the same pattern).
  useEffect(() => {
    api.workspaceApiKey(workspaceId).then((r) => setApiKey(r.api_key));
  }, [workspaceId]);

  async function copyKey() {
    if (!apiKey) return;
    await navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function regenerate() {
    setRegenerating(true);
    setError(null);
    try {
      const r = await api.regenerateWorkspaceApiKey(workspaceId);
      setApiKey(r.api_key);
      setRevealed(true);
      setConfirming(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to regenerate key");
    } finally {
      setRegenerating(false);
    }
  }

  if (!apiKey) return null;

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
        {copied && <span className="text-xs text-chart-5">Copied to clipboard</span>}

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
                  {regenerating ? "Regenerating..." : "Yes, regenerate now"}
                </Button>
                <Button variant="outline" size="sm" disabled={regenerating} onClick={() => setConfirming(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
        </div>
      </CardContent>
    </Card>
  );
}
