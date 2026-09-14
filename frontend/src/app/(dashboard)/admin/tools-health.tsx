"use client";

import { api } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { AsyncContent } from "@/components/ui/async-content";
import { Loader2 } from "lucide-react";

type Health = { tool: string; installed: boolean; version: string | null; response_ms: number | null };

// Used only for the loading state, so each tool's name (and a "checking"
// spinner) shows immediately instead of an anonymous skeleton until the
// --version probes return (#326). This is deliberately NOT the full tool
// list any more: backend/app/api/tools/health.py's VERSION_COMMANDS is now
// derived from the registry (16 tools and growing), and hardcoding that
// list here a second time is exactly the drift #75/#326 already burned us
// on once. Whatever the backend actually reports (allTools below) is the
// real source of truth; this is just a friendlier spinner for the four
// tools most likely to be waited on.
const TOOLS = ["semgrep", "gitleaks", "trivy", "gosec"] as const;

export function ToolsHealth() {
  const asyncState = useAsyncData<Health[]>(() => api.toolsHealth());
  const { data: health, status, refetch: refresh } = asyncState;
  const checking = status === "loading";
  const byTool = new Map((health ?? []).map((h) => [h.tool, h]));

  // Union of known tools and any tools the backend reported (in case new
  // tools are added server-side without updating this list).
  const allTools = Array.from(new Set([...TOOLS, ...(health ?? []).map((h) => h.tool)]));


  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Real <code className="text-foreground">--version</code> subprocess checks against the tools installed on
          this host, not simulated status.
        </p>
        <Button size="sm" variant="outline" onClick={refresh} disabled={checking}>
          {checking ? "Checking..." : "Recheck"}
        </Button>
      </div>

      <AsyncContent
        state={asyncState}
        itemNoun="tools"
        loadingFallback={
          <div className="grid gap-3 md:grid-cols-2">
            {TOOLS.map((tool) => (
              <Card key={tool} className="border-border bg-card">
                <CardContent className="flex items-center justify-between px-4 py-3">
                  <div>
                    <div className="font-medium capitalize text-foreground">{tool}</div>
                    <div className="mt-1 text-xs text-muted-foreground">—</div>
                  </div>
                  <Badge variant="outline" className="border-muted-foreground/20 text-muted-foreground">
                    <Loader2 className="h-3 w-3 animate-spin motion-reduce:animate-none" aria-hidden="true" /> checking
                  </Badge>
                </CardContent>
              </Card>
            ))}
          </div>
        }
      >
        {() => (
          <div className="grid gap-3 md:grid-cols-2">
            {allTools.map((tool) => {
              const h = byTool.get(tool);
              if (!h) {
                // A tool with no entry in the response is unmeasured, not
                // failing -- the backend never ran a check for it (a stale
                // registry/frontend version mismatch, most plausibly). Per
                // AGENTS.md's "never render confident 0 for unmeasured
                // data": StatusBadge's own "unknown" variant (muted, not
                // destructive) is the honest rendering here, the same
                // primitive already used to draw the completed/failed
                // badges below. Reusing it, rather than hand-rolling a red
                // Badge, is what used to make this indistinguishable from
                // a real failure at a glance.
                return (
                  <Card key={tool} className="border-border bg-card">
                    <CardContent className="flex items-center justify-between px-4 py-3">
                      <div>
                        <div className="font-medium capitalize text-foreground">{tool}</div>
                        <div className="mt-1 text-xs text-muted-foreground">—</div>
                      </div>
                      <StatusBadge status="unknown" label="not checked" />
                    </CardContent>
                  </Card>
                );
              }
              return (
                <Card key={h.tool} className="border-border bg-card">
                  <CardContent className="flex items-center justify-between px-4 py-3">
                    <div>
                      <div className="font-medium capitalize text-foreground">{h.tool}</div>
                      <div className="mt-1 text-xs text-muted-foreground">{h.version ?? "—"}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      {h.response_ms !== null && <span className="text-xs text-muted-foreground">{h.response_ms}ms</span>}
                      {h.installed && h.version ? (
                        <StatusBadge status="completed" label="healthy" />
                      ) : (
                        <StatusBadge status="failed" label={h.installed ? "error" : "not installed"} />
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </AsyncContent>
    </div>
  );
}
