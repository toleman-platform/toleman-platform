"use client";

import { api } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckCircle2, XCircle } from "lucide-react";

type Health = { tool: string; installed: boolean; version: string | null; response_ms: number | null };

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
        {health === null && !error &&
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="border-border bg-card">
              <CardContent className="flex items-center justify-between px-4 py-3">
                <div className="flex flex-col gap-2">
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-3 w-16" />
                </div>
                <Skeleton className="h-5 w-16" />
              </CardContent>
            </Card>
          ))}
        {health?.map((h) => (
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
        ))}
      </div>
    </div>
  );
}
