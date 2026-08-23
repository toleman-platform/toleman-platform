"use client";

import { api } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";

type Health = { tool: string; installed: boolean; version: string | null; response_ms: number | null };

// Mirrors VERSION_COMMANDS in backend/app/api/tools/health.py. The tab's scope
// is fixed to these four originally-integrated scanners, so cards are rendered
// from this list rather than learned from the response — which is what lets
// each tool's name (and a "checking" state) show immediately instead of
// anonymous skeletons until the sequential --version probes return (#326).
const TOOLS = ["semgrep", "gitleaks", "trivy", "gosec"] as const;

export function ToolsHealth() {
  // Previously this had no rejection path at all: if the health check failed,
  // `setHealth` never ran and the skeleton stayed on screen forever, which
  // reads as "still checking" rather than "the check failed".
  const {
    data: health,
    error,
    status,
    refetch: refresh,
  } = useAsyncData<Health[]>(() => api.toolsHealth());
  const checking = status === "loading";
  const byTool = new Map((health ?? []).map((h) => [h.tool, h]));

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

      {error && <p className="text-sm text-destructive">{error.message}</p>}

      <div className="grid gap-3 md:grid-cols-2">
        {TOOLS.map((tool) => {
          const h = byTool.get(tool);
          if (!h) {
            return (
              <Card key={tool} className="border-border bg-card">
                <CardContent className="flex items-center justify-between px-4 py-3">
                  <div>
                    <div className="font-medium capitalize text-foreground">{tool}</div>
                    <div className="mt-1 text-xs text-muted-foreground">—</div>
                  </div>
                  {error ? (
                    <Badge variant="outline" className="border-destructive/20 bg-destructive/10 text-destructive">
                      <XCircle className="h-3 w-3" /> failed
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-muted-foreground/20 text-muted-foreground">
                      <Loader2 className="h-3 w-3 animate-spin motion-reduce:animate-none" aria-hidden="true" /> checking
                    </Badge>
                  )}
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
                    <Badge variant="outline" className="border-chart-5/20 bg-chart-5/10 text-chart-5">
                      <CheckCircle2 className="h-3 w-3" /> healthy
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-destructive/20 bg-destructive/10 text-destructive">
                      <XCircle className="h-3 w-3" /> {h.installed ? "error" : "not installed"}
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
