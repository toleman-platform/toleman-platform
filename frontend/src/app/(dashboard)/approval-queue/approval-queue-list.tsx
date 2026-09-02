"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { IGNORE_STATUS_COLOR } from "@/lib/severity";
import { ActivityPagination, pageSizeFromParams } from "@/components/activity-pagination";
import { cn } from "@/lib/utils";
import { SeverityChip } from "@/components/ui/severity-chip";
import { AlertBanner } from "@/components/ui/alert-banner";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, History as HistoryIcon } from "lucide-react";

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

  async function approve(id: number) {
    setBusyId(id);
    try {
      await api.approveIgnore(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function reject(id: number) {
    setBusyId(id);
    try {
      await api.rejectIgnore(id);
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function revoke(id: number) {
    setBusyId(id);
    try {
      await api.revokeIgnore(id);
      refreshHistory();
    } finally {
      setBusyId(null);
    }
  }

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
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busyId === f.id}
                          onClick={() => approve(f.id)}
                          className="h-7 text-xs"
                        >
                          Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busyId === f.id}
                          onClick={() => reject(f.id)}
                          className="h-7 text-xs text-destructive"
                        >
                          Reject
                        </Button>
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
                          {f.ignore_reviewed_at ? ` · ${new Date(f.ignore_reviewed_at).toLocaleString()}` : ""}
                        </div>
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
                            onClick={() => revoke(f.id)}
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
    </div>
  );
}
