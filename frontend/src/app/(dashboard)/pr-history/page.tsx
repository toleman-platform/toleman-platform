"use client";

import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { api, ApiError, Target, PullRequest } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import { PrScanAction } from "@/components/pr-scan-action";
import { PrGuardrailLog } from "@/components/pr-guardrail-log";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { DocGenStep, DocumentGeneratorPanel } from "@/components/document-generator-panel";
import { GitPullRequest } from "lucide-react";
import { ActivityPagination } from "@/components/activity-pagination";
import { pageSizeFromParams } from "@/lib/pagination";

function isSessionError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

export default function PrHistoryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [prs, setPrs] = useState<PullRequest[]>([]);
  const prSearchParams = useSearchParams();
  const prPageSize = pageSizeFromParams(prSearchParams.get("page_size") ?? undefined);
  const prPageRaw = Math.max(1, Number(prSearchParams.get("page") ?? "1") || 1);
  const prTotalPages = Math.max(1, Math.ceil(prs.length / prPageSize));
  const prPage = Math.min(prPageRaw, prTotalPages);
  const visiblePrs = prs.slice((prPage - 1) * prPageSize, prPage * prPageSize);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = useState(false);

  const isOrgWide = targetId === ALL_TARGETS;

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  const loadPrs = useCallback(() => {
    // GitHub's PR API is inherently single-repo, so "All repositories" has
    // no PR list to fetch here -- it only drives the aggregated PR
    // Guardrail scan log below (issue #64).
    if (targetId === null || isOrgWide) {
      setPrs([]);
      return;
    }
    setLoading(true);
    setError(null);
    setSessionExpired(false);
    api
      .prs(targetId)
      .then(setPrs)
      .catch((e) => {
        if (isSessionError(e)) setSessionExpired(true);
        else setError(e instanceof Error ? e.message : "failed to load PRs");
      })
      .finally(() => setLoading(false));
  }, [targetId, isOrgWide]);

  useEffect(() => {
    loadPrs();
  }, [loadPrs]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">PR History</h1>
        <p className="text-sm text-muted-foreground">
          Live pull requests from GitHub. Trigger a PR Guardrail diff-scan on any open PR to
          surface net-new vulnerabilities before merge.
        </p>
      </div>

      <DocumentGeneratorPanel
        layout="stacked"
        steps={[
          <DocGenStep key="target" n={1} label="Repo">
            <TargetPicker targets={targets} value={targetId} onChange={setTargetId} allowAll />
          </DocGenStep>,
        ]}
      />

      {isOrgWide ? (
        <p className="text-sm text-muted-foreground">
          Live GitHub pull requests are per-repository -- select a single repository above to see
          its open PRs. Showing the aggregated PR Guardrail scan history across all repositories
          below.
        </p>
      ) : (
        <>
          {sessionExpired && (
            <ErrorState
              title="Your session has expired"
              description="You were signed out after a period of inactivity, or your access was revoked by an admin. Log back in to keep viewing PR guardrail history."
              action={
                <Button size="sm" asChild>
                  <Link href="/login">Log in again</Link>
                </Button>
              }
            />
          )}

          {!sessionExpired && error && <ErrorState description={error} onRetry={loadPrs} />}

          {!sessionExpired && loading && <SkeletonList count={4} />}

          {!sessionExpired && !loading && (
            <div className="flex flex-col gap-2">
              {/* PR History rendered every PR the GitHub API returned, with no
                  pager. On an active repo that is an unbounded list. Paged
                  client-side because the PRs are already fetched here. */}
              <ActivityPagination total={prs.length} page={prPage} pageSize={prPageSize} position="top" />
              {visiblePrs.map((pr) => (
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
