"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { api, ApiError, type Target, type PullRequest } from "@/lib/api";
import { safeHref } from "@/lib/security/safe-href";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Button } from "@/components/ui/button";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import { PrScanAction, PrGuardrailLog } from "@/components/features/scans";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { DocumentGeneratorPanel, DocGenStep } from "@/components/features/intelligence";
import { GitPullRequest } from "lucide-react";
import { PageHeader } from "@/components/ui/page-header";
import { ActivityPagination } from "@/components/activity-pagination";
import { pageSizeFromParams } from "@/lib/pagination";

function isSessionError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

// Parses a positive integer id out of a URL search param, e.g. the
// `target_id`/`pr_scan_id`/`ignore_finding` params on the "view"/"request
// ignore" links pr_guardrail_executor.py posts in PR comments -- ALL_TARGETS
// (0) and anything malformed both fall through to null rather than seeding
// a bogus selection.
function positiveIntParam(params: URLSearchParams, key: string): number | null {
  const n = Number(params.get(key));
  return Number.isInteger(n) && n > 0 ? n : null;
}

export default function PrHistoryPage() {
  const prSearchParams = useSearchParams();
  // Deep-linking from a PR comment's "view"/"request ignore" links (#385):
  // seeded once from the URL so the page opens on the right repo instead of
  // whichever target happens to be first in the list. Only the initial
  // value; a later manual repo switch is a real state change afterward.
  const [chosenTargetId, setChosenTargetId] = useState<number | null>(() =>
    positiveIntParam(prSearchParams, "target_id"),
  );
  const linkedScanId = positiveIntParam(prSearchParams, "pr_scan_id");
  const linkedIgnoreFindingId = positiveIntParam(prSearchParams, "ignore_finding");

  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets());
  const targets = targetsData ?? [];
  const targetId = chosenTargetId ?? targets[0]?.id ?? null;
  const setTargetId = setChosenTargetId;

  const isOrgWide = targetId === ALL_TARGETS;

  // GitHub's PR API is inherently single-repo, so "All repositories" has no
  // PR list to fetch here; it only drives the aggregated PR Guardrail scan
  // log below (issue #64).
  const {
    data: prsData,
    error: loadError,
    isInitialLoading: loading,
    refetch: loadPrs,
  } = useAsyncData<PullRequest[]>(() => api.prs(targetId!), {
    enabled: targetId !== null && !isOrgWide,
    deps: [targetId, isOrgWide],
  });
  const prs = isOrgWide ? [] : (prsData ?? []);

  // A 401 is not a page error; it means the GitHub session lapsed, and the
  // page has a dedicated reconnect affordance for it.
  const sessionExpired = loadError !== null && isSessionError(loadError);
  const error = sessionExpired ? null : (loadError?.message ?? null);

  const prPageSize = pageSizeFromParams(prSearchParams.get("page_size") ?? undefined);
  const prPageRaw = Math.max(1, Number(prSearchParams.get("page") ?? "1") || 1);
  const prTotalPages = Math.max(1, Math.ceil(prs.length / prPageSize));
  const prPage = Math.min(prPageRaw, prTotalPages);
  const visiblePrs = prs.slice((prPage - 1) * prPageSize, prPage * prPageSize);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="PR History"
        description="Live pull requests from GitHub. Trigger a PR Guardrail diff-scan on any open PR to surface net-new vulnerabilities before merge."
      />

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
          Live GitHub pull requests are per-repository, select a single repository above to see
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
                      <a href={safeHref(pr.url)} target="_blank" rel="noreferrer" className="font-medium text-foreground hover:underline">
                        #{pr.number} {pr.title}
                      </a>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {pr.author} · opened {new Date(pr.created_at).toLocaleDateString()}
                        {pr.merged_at ? ` · merged ${new Date(pr.merged_at).toLocaleDateString()}` : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <StatusBadge
                        status={pr.state === "open" ? "running" : pr.state === "merged" ? "completed" : "blocked"}
                        label={pr.state}
                      />
                      {pr.state === "open" && targetId !== null ? (
                        <PrScanAction targetId={targetId} prNumber={pr.number} />
                      ) : (
                        <StatusBadge
                          status={pr.scan_status === "passed" ? "completed" : pr.scan_status === "failed" ? "failed" : "queued"}
                          label={pr.scan_status}
                        />
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

      <PrGuardrailLog targetId={targetId} initialScanId={linkedScanId} initialIgnoreFindingId={linkedIgnoreFindingId} />
    </div>
  );
}
