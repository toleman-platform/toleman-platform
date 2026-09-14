"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { api, ApiError, type Target, type PullRequest, type PullRequestState } from "@/lib/api";
import { safeHref } from "@/lib/security/safe-href";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TargetPicker, ALL_TARGETS } from "@/components/features/targets";
import { PrScanAction, PrGuardrailLog, ScanFindings } from "@/components/features/scans";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { DocumentGeneratorPanel, DocGenStep } from "@/components/features/intelligence";
import { ChevronDown, ChevronRight, GitPullRequest } from "lucide-react";
import { SEVERITY_COLOR } from "@/lib/severity";
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

// The finding a PR comment's "view" link points at, out of that link's
// `#finding-{id}` fragment (see _finding_ref_link in
// backend/app/core/pr_guardrail_executor.py). Read from the fragment rather
// than a query param so every comment already posted to GitHub -- the links
// in them are permanent -- starts working too, instead of only comments
// written after this deploys.
function findingIdFromHash(hash: string): number | null {
  const match = /^#finding-(\d+)$/.exec(hash);
  if (!match) return null;
  const n = Number(match[1]);
  return Number.isInteger(n) && n > 0 ? n : null;
}

// (#443-adjacent) A reviewer opening PR History is almost always asking about
// work in flight. Closed and merged PRs are history that pushes the open ones
// off the first page on any repo with a few months behind it, so the list
// opens on "Open" and the other states are a deliberate choice.
const PR_STATE_FILTERS: { value: PullRequestState | "all"; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "merged", label: "Merged" },
  { value: "closed", label: "Closed" },
  { value: "all", label: "All" },
];

const DEFAULT_PR_STATE: PullRequestState | "all" = "open";

function prStateBadgeStatus(state: PullRequestState) {
  if (state === "open") return "running";
  return state === "merged" ? "completed" : "blocked";
}

function scanBadgeStatus(scanStatus: string) {
  if (scanStatus === "passed") return "completed";
  if (scanStatus === "blocked" || scanStatus === "error") return "failed";
  if (scanStatus === "running") return "running";
  return "queued";
}

/**
 * One row of the live-PR list, expandable into the vulnerabilities the PR's
 * latest guardrail scan found.
 *
 * Before this, the PR list showed a scan verdict and nothing else: to see
 * *what* was found on a blocked PR you had to scroll past the list, find the
 * same PR again in the audit log below, and expand it there. The findings are
 * the reason anyone reads this page, so the row that reports a verdict is the
 * row that opens onto its evidence. Rendered with the same ScanFindings the
 * audit log uses, so the two cannot drift apart.
 */
function PrRow({
  pr,
  targetId,
  expanded,
  onToggle,
}: {
  pr: PullRequest;
  targetId: number | null;
  expanded: boolean;
  onToggle: () => void;
}) {
  const scanId = pr.latest_scan_id;
  const hasFindings = scanId !== null && pr.new_findings_count > 0;

  return (
    <Card className="border-border bg-card">
      <CardContent className="px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-start gap-2">
            {scanId !== null ? (
              <button
                type="button"
                onClick={onToggle}
                aria-expanded={expanded}
                aria-label={expanded ? `Hide findings for PR #${pr.number}` : `Show findings for PR #${pr.number}`}
                className="mt-0.5 shrink-0 text-muted-foreground hover:text-foreground"
              >
                {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </button>
            ) : (
              // Keeps the titles of scanned and unscanned PRs on one left
              // edge rather than letting rows jog sideways down the list.
              <span className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            )}
            <div className="min-w-0">
              <a
                href={safeHref(pr.url)}
                target="_blank"
                rel="noreferrer"
                className="font-medium text-foreground hover:underline"
              >
                #{pr.number} {pr.title}
              </a>
              <div className="mt-1 text-xs text-muted-foreground">
                {pr.author} · opened {new Date(pr.created_at).toLocaleDateString()}
                {pr.merged_at ? ` · merged ${new Date(pr.merged_at).toLocaleDateString()}` : ""}
              </div>
              {hasFindings && (
                <div className="mt-1 flex items-center gap-2 text-xs">
                  <Badge
                    variant="outline"
                    className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${
                      (pr.highest_new_severity && SEVERITY_COLOR[pr.highest_new_severity]) ||
                      "text-muted-foreground"
                    }`}
                  >
                    {pr.highest_new_severity ?? "finding"}
                  </Badge>
                  <button
                    type="button"
                    onClick={onToggle}
                    className="text-muted-foreground underline hover:text-foreground"
                  >
                    {pr.new_findings_count} net-new vulnerability finding
                    {pr.new_findings_count === 1 ? "" : "s"}
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <StatusBadge status={prStateBadgeStatus(pr.state)} label={pr.state} />
            {pr.state === "open" && targetId !== null ? (
              <PrScanAction targetId={targetId} prNumber={pr.number} />
            ) : (
              <StatusBadge status={scanBadgeStatus(pr.scan_status)} label={pr.scan_status} />
            )}
          </div>
        </div>

        {expanded && scanId !== null && (
          <div className="mt-3 border-t border-border pt-3">
            <ScanFindings scanId={scanId} />
          </div>
        )}
      </CardContent>
    </Card>
  );
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

  // useSearchParams cannot supply this: a URL fragment never leaves the
  // browser, so the server genuinely does not have it. Read once at mount,
  // the same "initial value only" treatment as chosenTargetId above. The
  // server-side pass sees no window and yields null, which changes nothing
  // it renders -- the findings this points into are fetched client-side and
  // do not exist in the server markup at all.
  const [linkedFindingId] = useState<number | null>(() =>
    typeof window === "undefined" ? null : findingIdFromHash(window.location.hash),
  );

  const [prState, setPrState] = useState<PullRequestState | "all">(DEFAULT_PR_STATE);
  // Which PR row is open, as {repo, PR number}: a PR number is only unique
  // within one repository, so keying on the number alone left a row expanded
  // across a repo switch and fetched an unrelated scan's findings under the
  // other repo's PR of the same number.
  const [expandedPr, setExpandedPr] = useState<{ targetId: number; prNumber: number } | null>(null);

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
  } = useAsyncData<PullRequest[]>(() => api.prs(targetId!, prState), {
    enabled: targetId !== null && !isOrgWide,
    deps: [targetId, isOrgWide, prState],
  });
  // GitHub answers the state filter (see api.prs): narrowing a fetched page
  // here instead would report "no open pull requests" on any repo that closes
  // PRs faster than a page of them is opened.
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
          <DocGenStep key="state" n={2} label="PR state">
            <select
              className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              aria-label="PR state"
              value={prState}
              onChange={(e) => setPrState(e.target.value as PullRequestState | "all")}
            >
              {PR_STATE_FILTERS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
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
                <PrRow
                  key={pr.number}
                  pr={pr}
                  targetId={targetId}
                  expanded={
                    expandedPr?.targetId === targetId && expandedPr?.prNumber === pr.number
                  }
                  onToggle={() =>
                    setExpandedPr((open) =>
                      open?.targetId === targetId && open?.prNumber === pr.number
                        ? null
                        : { targetId: targetId!, prNumber: pr.number },
                    )
                  }
                />
              ))}
              {prs.length === 0 && targetId !== null && (
                <EmptyState
                  icon={GitPullRequest}
                  title={prState === "all" ? "No pull requests found" : `No ${prState} pull requests`}
                  description={
                    prState === "all"
                      ? "Nothing has been opened against this target yet."
                      : `Nothing ${prState} on this target right now, switch the PR state filter to see the rest.`
                  }
                  bare
                />
              )}
            </div>
          )}
        </>
      )}

      <PrGuardrailLog
        targetId={targetId}
        initialScanId={linkedScanId}
        initialIgnoreFindingId={linkedIgnoreFindingId}
        initialFindingId={linkedFindingId}
      />
    </div>
  );
}
