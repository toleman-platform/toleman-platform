"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { api, type PrGuardrailFinding } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { SkeletonList } from "@/components/ui/skeleton";
import { IGNORE_STATUS_COLOR } from "@/lib/severity";
import { ActivityPagination, pageSizeFromParams } from "@/components/activity-pagination";
import { cn } from "@/lib/utils";
import { SeverityChip } from "@/components/ui/severity-chip";
import { AlertBanner } from "@/components/ui/alert-banner";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, History as HistoryIcon } from "lucide-react";
import { Timestamp } from "@/components/ui/timestamp";

// Split into two sub-pages (query-param tabs, same convention as
// targets/[id]/target-tabs.tsx: tab state lives in the URL, not component
// state, so a security reviewer can link someone straight to "History"),
// each now genuinely paginated -- a workspace running PR Guardrail for a
// while accumulates far more pending requests and reviewed decisions than
// fit on one screen, and the old unpaged lists just kept growing forever.
const TABS = [
  { id: "requests", label: "Approval Requests" },
  { id: "history", label: "History" },
] as const;
type Tab = (typeof TABS)[number]["id"];

// The History tab's "X by <reviewer>" line covers every decided
// ignore_status (approved/rejected/revoked, never "none"/"requested" --
// those live in the Approval Requests tab instead).
const DECISION_LABEL: Record<string, string> = {
  approved: "Approved",
  rejected: "Rejected",
  revoked: "Revoked",
};

function normalizeTab(raw: string | null): Tab {
  return TABS.some((t) => t.id === raw) ? (raw as Tab) : "requests";
}

export function ApprovalQueue() {
  const [busyId, setBusyId] = useState<number | null>(null);
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const tab = normalizeTab(searchParams.get("tab"));
  const page = Math.max(1, Number(searchParams.get("page")) || 1);
  const pageSize = pageSizeFromParams(searchParams.get("page_size") ?? undefined);

  const {
    data: pendingResult,
    error: loadError,
    refetch: refresh,
  } = useAsyncData(() => api.getPendingIgnoreRequests(page, pageSize), {
    enabled: tab === "requests",
    deps: [tab, page, pageSize],
  });
  const error = loadError?.message ?? null;
  const findings = pendingResult?.items ?? null;

  const {
    data: historyResult,
    error: historyLoadError,
    refetch: refreshHistory,
  } = useAsyncData(() => api.getIgnoreRequestHistory(page, pageSize), {
    enabled: tab === "history",
    deps: [tab, page, pageSize],
  });
  const historyError = historyLoadError?.message ?? null;
  const history = historyResult?.items ?? null;

  // All three decisions used to be `try`/`finally` with no `catch`. On a
  // failed call the spinner cleared, the row did not change, and the reviewer
  // got no signal whatsoever -- so the natural read is "my click didn't
  // register", and the natural next move is to click again. The error is
  // pinned to the row it belongs to rather than to a page-level banner.
  const [rowError, setRowError] = useState<{ id: number; message: string } | null>(null);

  // Approve permanently suppresses a security finding; revoke reverses a
  // prior approval and can put a merge block back. Both get a confirmation
  // that states what changes. Reject is left un-gated by a confirm dialog:
  // it denies a request without changing what the guardrail enforces, and
  // the developer can ask again. It still needs a typed reason (the whole
  // point of this column existing), so "Reject" expands an inline field
  // rather than firing immediately.
  const [pending, setPending] = useState<{ finding: PrGuardrailFinding; action: "approve" | "revoke" } | null>(null);
  const [rejecting, setRejecting] = useState<{ id: number; reason: string } | null>(null);

  async function run(id: number, action: () => Promise<unknown>, after: () => void, failureMessage: string) {
    setBusyId(id);
    setRowError(null);
    try {
      await action();
      setPending(null);
      after();
    } catch (e) {
      setRowError({ id, message: e instanceof Error ? e.message : failureMessage });
    } finally {
      setBusyId(null);
    }
  }

  const approve = (id: number) =>
    run(id, () => api.approveIgnore(id), refresh, "failed to approve this ignore request");
  const reject = (id: number, reason: string) =>
    run(
      id,
      () => api.rejectIgnore(id, reason),
      () => {
        setRejecting(null);
        refresh();
      },
      "failed to reject this ignore request",
    );
  const revoke = (id: number) =>
    run(id, () => api.revokeIgnore(id), refreshHistory, "failed to revoke this approval");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <Link
            key={t.id}
            href={`${pathname}?tab=${t.id}`}
            scroll={false}
            aria-current={tab === t.id ? "page" : undefined}
            className={cn(
              "px-3 py-2 text-sm font-medium transition-colors",
              tab === t.id
                ? "border-b-2 border-primary text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
          </Link>
        ))}
      </div>

      {tab === "requests" && (
        <div className="flex flex-col gap-3">
          {error && <AlertBanner tone="critical">{error}</AlertBanner>}
          {findings === null && !error && <SkeletonList count={3} />}

          {pendingResult && (
            <ActivityPagination total={pendingResult.total} page={page} pageSize={pageSize} position="top" />
          )}

          {findings !== null && (
            <div className="flex flex-col gap-2">
              {findings.map((f) => (
                <Card key={f.id} className="border-border bg-card">
                  <CardContent className="px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <SeverityChip severity={f.severity} size="sm" />
                          <span className="truncate text-sm font-medium text-foreground">{f.title}</span>
                        </div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">
                          {f.tool} · {f.file_path}
                          {f.line_start ? `:${f.line_start}` : ""} · {f.rule_id}
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          Requested by {f.ignore_requested_by}: {f.ignore_requested_reason}
                        </div>
                        {rowError?.id === f.id && (
                          <p role="alert" className="mt-1 text-xs text-destructive">
                            Nothing was changed: {rowError.message}
                          </p>
                        )}
                        {rejecting?.id === f.id && (
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <Input
                              autoFocus
                              className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
                              placeholder="Reason for rejecting"
                              value={rejecting.reason}
                              disabled={busyId === f.id}
                              onChange={(e) => setRejecting({ id: f.id, reason: e.target.value })}
                            />
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busyId === f.id || !rejecting.reason.trim()}
                              onClick={() => reject(f.id, rejecting.reason)}
                              className="h-7 text-xs text-destructive"
                            >
                              Confirm reject
                            </Button>
                            <button
                              onClick={() => setRejecting(null)}
                              disabled={busyId === f.id}
                              className="text-xs text-muted-foreground"
                            >
                              cancel
                            </button>
                          </div>
                        )}
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busyId === f.id}
                          onClick={() => setPending({ finding: f, action: "approve" })}
                          className="h-7 text-xs"
                        >
                          Approve
                        </Button>
                        {rejecting?.id !== f.id && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busyId === f.id}
                            onClick={() => setRejecting({ id: f.id, reason: "" })}
                            className="h-7 text-xs text-destructive"
                          >
                            Reject
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {findings.length === 0 && (
                <EmptyState
                  icon={CheckCircle2}
                  title="No pending ignore requests"
                  description="PR Guardrail findings a developer has requested be ignored will appear here."
                />
              )}
            </div>
          )}

          {pendingResult && (
            <ActivityPagination total={pendingResult.total} page={page} pageSize={pageSize} position="bottom" />
          )}
        </div>
      )}

      {tab === "history" && (
        <div className="flex flex-col gap-3">
          {historyError && <AlertBanner tone="critical">{historyError}</AlertBanner>}
          {history === null && !historyError && <SkeletonList count={3} />}

          {historyResult && (
            <ActivityPagination total={historyResult.total} page={page} pageSize={pageSize} position="top" />
          )}

          {history !== null && (
            <div className="flex flex-col gap-2">
              {history.map((f) => (
                <Card key={f.id} className="border-border bg-card">
                  <CardContent className="px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <SeverityChip severity={f.severity} size="sm" />
                          <span className="truncate text-sm font-medium text-foreground">{f.title}</span>
                        </div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">
                          {f.tool} · {f.file_path}
                          {f.line_start ? `:${f.line_start}` : ""} · {f.rule_id}
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          Requested by {f.ignore_requested_by}: {f.ignore_requested_reason}
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {DECISION_LABEL[f.ignore_status] || f.ignore_status} by {f.ignore_reviewed_by}
                          {f.ignore_reviewed_at ? (
                            <>
                              {" · "}
                              <Timestamp value={f.ignore_reviewed_at} />
                            </>
                          ) : (
                            ""
                          )}
                        </div>
                        {f.ignore_status === "rejected" && (
                          <div className="mt-1 text-xs text-muted-foreground">
                            Reason: {f.reject_reason || "not recorded"}
                          </div>
                        )}
                        {rowError?.id === f.id && (
                          <p role="alert" className="mt-1 text-xs text-destructive">
                            Nothing was changed: {rowError.message}
                          </p>
                        )}
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Badge variant="outline" className={IGNORE_STATUS_COLOR[f.ignore_status] || "text-muted-foreground"}>
                          {f.ignore_status}
                        </Badge>
                        {f.ignore_status === "approved" && (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busyId === f.id}
                            onClick={() => setPending({ finding: f, action: "revoke" })}
                            className="h-7 text-xs text-destructive"
                          >
                            Revoke
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {history.length === 0 && (
                <EmptyState
                  icon={HistoryIcon}
                  title="No ignore requests reviewed yet"
                  description="When a security reviewer approves or rejects an ignore request, it will appear here."
                />
              )}
            </div>
          )}

          {historyResult && (
            <ActivityPagination total={historyResult.total} page={page} pageSize={pageSize} position="bottom" />
          )}
        </div>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={pending?.action === "approve" ? "Approve this ignore request?" : "Revoke this approval?"}
        description={
          <>
            {pending?.action === "approve" ? (
              <>
                <strong>{pending.finding.title}</strong> ({pending.finding.severity}) stops blocking this pull request
                and is suppressed on the main findings list too. The developer&apos;s stated reason was:{" "}
                <em>{pending.finding.ignore_requested_reason || "none given"}</em>.
              </>
            ) : (
              <>
                <strong>{pending?.finding.title}</strong> comes back as an open finding and the PR comment reverts to
                a live &ldquo;request ignore&rdquo; link. If this was the only approved finding keeping the scan
                unblocked, the pull request will be blocked again.
              </>
            )}
            {/* The row-level error lives behind this overlay while the dialog
                is open, so repeat it here rather than closing over a failure. */}
            {pending && rowError?.id === pending.finding.id && (
              <span className="mt-2 block text-destructive">Nothing was changed: {rowError.message}</span>
            )}
          </>
        }
        confirmLabel={pending?.action === "approve" ? "Approve ignore" : "Revoke approval"}
        tone={pending?.action === "approve" ? "default" : "destructive"}
        loading={pending !== null && busyId === pending.finding.id}
        onConfirm={() => {
          if (!pending) return;
          if (pending.action === "approve") approve(pending.finding.id);
          else revoke(pending.finding.id);
        }}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
