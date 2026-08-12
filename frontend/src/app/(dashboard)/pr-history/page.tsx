"use client";

import { useEffect, useState } from "react";
import { api, Target, PullRequest } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TargetPicker } from "@/components/target-picker";
import { PrScanAction } from "@/components/pr-scan-action";
import { PrGuardrailLog } from "@/components/pr-guardrail-log";
import { SkeletonList } from "@/components/ui/skeleton";

export default function PrHistoryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [prs, setPrs] = useState<PullRequest[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  useEffect(() => {
    if (targetId === null) return;
    setLoading(true);
    setError(null);
    api
      .prs(targetId)
      .then(setPrs)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load PRs"))
      .finally(() => setLoading(false));
  }, [targetId]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">PR History</h1>
        <p className="text-sm text-muted-foreground">
          Live pull requests from GitHub. Trigger a PR Guardrail diff-scan on any open PR to
          surface net-new vulnerabilities before merge.
        </p>
      </div>

      <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />

      {error && <p className="text-sm text-destructive">{error}</p>}

      {loading && <SkeletonList count={4} />}

      {!loading && (
        <div className="flex flex-col gap-2">
          {prs.map((pr) => (
            <Card key={pr.number} className="border-border bg-card">
              <CardContent className="flex items-center justify-between px-4 py-3">
                <div>
                  <a href={pr.url} target="_blank" rel="noreferrer" className="font-medium text-foreground hover:underline">
                    #{pr.number} {pr.title}
                  </a>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {pr.author} · opened {new Date(pr.created_at).toLocaleDateString()}
                    {pr.merged_at ? ` · merged ${new Date(pr.merged_at).toLocaleDateString()}` : ""}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{pr.state}</Badge>
                  {pr.state === "open" && targetId !== null ? (
                    <PrScanAction targetId={targetId} prNumber={pr.number} />
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground">
                      {pr.scan_status}
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
          {prs.length === 0 && targetId !== null && (
            <p className="text-sm text-muted-foreground">No pull requests found for this target.</p>
          )}
        </div>
      )}

      <PrGuardrailLog targetId={targetId} />
    </div>
  );
}
