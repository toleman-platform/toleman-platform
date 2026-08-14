"use client";

import { useEffect, useState } from "react";
import { api, Target, PullRequest } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import { PrScanAction } from "@/components/pr-scan-action";
import { PrGuardrailLog } from "@/components/pr-guardrail-log";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { GitPullRequest } from "lucide-react";

export default function PrHistoryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [prs, setPrs] = useState<PullRequest[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isOrgWide = targetId === ALL_TARGETS;

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  useEffect(() => {
    // GitHub's PR API is inherently single-repo, so "All repositories" has
    // no PR list to fetch here -- it only drives the aggregated PR
    // Guardrail scan log below (issue #64).
    if (targetId === null || isOrgWide) {
      setPrs([]);
      return;
    }
    setLoading(true);
    setError(null);
    api
      .prs(targetId)
      .then(setPrs)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load PRs"))
      .finally(() => setLoading(false));
  }, [targetId, isOrgWide]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">PR History</h1>
        <p className="text-sm text-muted-foreground">
          Live pull requests from GitHub. Trigger a PR Guardrail diff-scan on any open PR to
          surface net-new vulnerabilities before merge.
        </p>
      </div>

      <TargetPicker targets={targets} value={targetId} onChange={setTargetId} allowAll />

      {isOrgWide ? (
        <p className="text-sm text-muted-foreground">
          Live GitHub pull requests are per-repository -- select a single repository above to see
          its open PRs. Showing the aggregated PR Guardrail scan history across all repositories
          below.
        </p>
      ) : (
        <>
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
                <EmptyState icon={GitPullRequest} title="No pull requests found" description="Nothing has been opened against this target yet." bare />
              )}
            </div>
          )}
        </>
      )}

      <PrGuardrailLog targetId={targetId} />
    </div>
  );
}
