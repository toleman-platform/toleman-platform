"use client";

import { useState } from "react";
import Link from "next/link";
import { ExternalLink, ShieldQuestion } from "lucide-react";
import { api, ApiError, PrGuardrailFinding, PrGuardrailLogEntry, PrGuardrailOrgStats } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { IGNORE_STATUS_COLOR, SEVERITY_COLOR } from "@/lib/severity";
import { ALL_TARGETS } from "@/components/target-picker";

function isSessionError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

export const LOG_STATUS_COLOR: Record<string, string> = {
  running: "border-chart-1/20 bg-chart-1/10 text-chart-1",
  passed: "border-chart-5/20 bg-chart-5/10 text-chart-5",
  blocked: "border-destructive/20 bg-destructive/10 text-destructive",
  error: "border-border bg-muted text-muted-foreground",
  overridden: "border-chart-3/20 bg-chart-3/10 text-chart-3",
};

function OverrideAction({ entry, onOverridden }: { entry: PrGuardrailLogEntry; onOverridden: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    setSubmitting(true);
    try {
      await api.overridePrGuardrail(entry.id, reason);
      setOpen(false);
      setReason("");
      onOverridden();
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground underline hover:text-foreground">
        Override (Accept Risk)
      </button>
    );
  }

  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <Input
        className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
        placeholder="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />
      <Button size="sm" variant="outline" disabled={submitting || !reason} onClick={submit} className="h-7 text-xs">
        Confirm
      </Button>
      <button onClick={() => setOpen(false)} className="text-xs text-muted-foreground">
        cancel
      </button>
    </div>
  );
}

function RequestIgnoreAction({ finding, onRequested }: { finding: PrGuardrailFinding; onRequested: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    setSubmitting(true);
    try {
      await api.requestIgnoreFinding(finding.id, reason);
      setOpen(false);
      setReason("");
      onRequested();
    } finally {
      setSubmitting(false);
    }
  }

  if (finding.ignore_status !== "none") return null;

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-xs text-muted-foreground underline hover:text-foreground">
        Request Ignore
      </button>
    );
  }

  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <Input
        className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
        placeholder="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />
      <Button size="sm" variant="outline" disabled={submitting || !reason} onClick={submit} className="h-7 text-xs">
        Confirm
      </Button>
      <button onClick={() => setOpen(false)} className="text-xs text-muted-foreground">
        cancel
      </button>
    </div>
  );
}

function PrGuardrailFindingRow({ finding, onChanged }: { finding: PrGuardrailFinding; onChanged: () => void }) {
  return (
    <div className="rounded-md border border-border bg-secondary/40 px-3 py-2">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className={`shrink-0 px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${SEVERITY_COLOR[finding.severity] || "text-muted-foreground"}`}
            >
              {finding.severity}
            </Badge>
            <span className="truncate text-xs font-medium text-foreground">{finding.title}</span>
          </div>
          <div className="mt-1 truncate text-xs text-muted-foreground">
            {finding.tool} · {finding.file_path}
            {finding.line_start ? `:${finding.line_start}` : ""} · {finding.rule_id}
          </div>
          {finding.ignore_status === "requested" && (
            <div className="mt-1 text-xs text-muted-foreground">
              Ignore requested by {finding.ignore_requested_by}: {finding.ignore_requested_reason}
            </div>
          )}
          {(finding.ignore_status === "approved" || finding.ignore_status === "rejected") && (
            <div className="mt-1 text-xs text-muted-foreground">
              Ignore {finding.ignore_status} by {finding.ignore_reviewed_by}
              {finding.ignore_reviewed_at ? ` · ${new Date(finding.ignore_reviewed_at).toLocaleString()}` : ""}
            </div>
          )}
        </div>
        <Badge variant="outline" className={`shrink-0 ${IGNORE_STATUS_COLOR[finding.ignore_status] || "text-muted-foreground"}`}>
          {finding.ignore_status}
        </Badge>
      </div>
      <div className="mt-2">
        <RequestIgnoreAction finding={finding} onRequested={onChanged} />
      </div>
    </div>
  );
}

function ScanFindings({ scanId }: { scanId: number }) {
  const {
    data: findings,
    error,
    refetch: refresh,
  } = useAsyncData<PrGuardrailFinding[]>(() => api.getPrGuardrailFindings(scanId), {
    deps: [scanId],
  });

  if (error) return <p className="text-xs text-destructive">{error.message}</p>;
  if (findings === null) return <p className="text-xs text-muted-foreground">Loading findings...</p>;
  if (findings.length === 0) return <p className="text-xs text-muted-foreground">No persisted findings for this scan.</p>;

  return (
    <div className="flex flex-col gap-2">
      {findings.map((f) => (
        <PrGuardrailFindingRow key={f.id} finding={f} onChanged={refresh} />
      ))}
    </div>
  );
}

function OrgStatsBar({ stats }: { stats: PrGuardrailOrgStats }) {
  return (
    <div className="flex flex-wrap gap-2">
      <Badge variant="outline" className="text-foreground">
        {stats.total} total scan{stats.total === 1 ? "" : "s"}
      </Badge>
      <Badge variant="outline" className={LOG_STATUS_COLOR.passed}>
        {stats.passed} passed
      </Badge>
      <Badge variant="outline" className={LOG_STATUS_COLOR.blocked}>
        {stats.blocked} blocked
      </Badge>
      <Badge variant="outline" className={LOG_STATUS_COLOR.overridden}>
        {stats.overridden} overridden
      </Badge>
      {stats.running > 0 && (
        <Badge variant="outline" className={LOG_STATUS_COLOR.running}>
          {stats.running} running
        </Badge>
      )}
      {stats.error > 0 && (
        <Badge variant="outline" className={LOG_STATUS_COLOR.error}>
          {stats.error} error
        </Badge>
      )}
    </div>
  );
}

export function PrGuardrailLog({ targetId }: { targetId: number | null }) {
  const isOrgWide = targetId === ALL_TARGETS;
  const [expanded, setExpanded] = useState<number | null>(null);

  // The org-wide view carries aggregate stats; the per-repo one has none.
  // Returning both from a single fetcher keeps them in lockstep -- the two
  // separate state slots could previously show one repo's log beside another
  // view's stats if the requests interleaved.
  const {
    data,
    error: loadError,
    isInitialLoading: loading,
    refetch: refresh,
  } = useAsyncData<{ log: PrGuardrailLogEntry[]; stats: PrGuardrailOrgStats | null }>(
    () =>
      isOrgWide
        ? api.getPrGuardrailOrgLog().then((res) => ({ log: res.scans, stats: res.stats }))
        : api.getPrGuardrailLog(targetId!).then((entries) => ({ log: entries, stats: null })),
    { enabled: targetId !== null, deps: [targetId, isOrgWide] },
  );
  const log = data?.log ?? [];
  const stats = data?.stats ?? null;

  // A 401 means the GitHub session lapsed, which has its own reconnect
  // affordance -- it is not a generic page error.
  const sessionExpired = loadError !== null && isSessionError(loadError);
  const error = sessionExpired ? null : (loadError?.message ?? null);

  if (targetId === null) return null;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="text-lg font-semibold text-foreground">PR Audit &amp; Discovery Log</h2>
        <p className="text-sm text-muted-foreground">
          {isOrgWide
            ? "History of PR Guardrail scans across every repository you can access."
            : "History of PR Guardrail scans for this target."}
        </p>
      </div>

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

      {!sessionExpired && stats && <OrgStatsBar stats={stats} />}

      {!sessionExpired && loading && <SkeletonList count={3} />}
      {!sessionExpired && error && <ErrorState description={error} onRetry={refresh} />}

      {!sessionExpired && (
      <div className="flex flex-col gap-2">
        {log.map((entry) => {
          const isExpanded = expanded === entry.id;
          return (
            <Card key={entry.id} className="border-border bg-card">
              <CardContent className="px-4 py-3">
                <button
                  className="flex w-full items-center justify-between gap-3 text-left"
                  onClick={() => setExpanded(isExpanded ? null : entry.id)}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-1 truncate text-sm font-medium text-foreground">
                      <span className="truncate">
                        #{entry.pr_number} {entry.pr_title}
                      </span>
                      {isOrgWide && entry.target_name && (
                        <Badge variant="outline" className="align-middle text-xs text-muted-foreground">
                          {entry.target_name}
                        </Badge>
                      )}
                      {entry.pr_url && (
                        <a
                          href={entry.pr_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Open this PR on GitHub"
                          onClick={(e) => e.stopPropagation()}
                          className="shrink-0 text-muted-foreground hover:text-foreground"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                    <div className="mt-1 truncate text-xs text-muted-foreground">
                      {entry.branch} · created {new Date(entry.created_at).toLocaleString()}
                      {entry.completed_at ? ` · completed ${new Date(entry.completed_at).toLocaleString()}` : ""}
                    </div>
                    {entry.status === "overridden" && entry.override_reason && (
                      <div className="mt-1 text-xs text-muted-foreground">Override reason: {entry.override_reason}</div>
                    )}
                    {/* GH-01: a scan where an assigned tool failed is
                        inconclusive, not clean -- say so next to the counts
                        rather than letting "0 new findings" read as a pass. */}
                    {entry.status_delivery_error && (
                      <div className="mt-1 text-xs text-destructive">{entry.status_delivery_error}</div>
                    )}
                    {entry.tools_failed?.length > 0 && (
                      <div className="mt-1 text-xs text-destructive">
                        {entry.tools_failed.join(", ")} failed to run — PR not fully scanned
                      </div>
                    )}
                    {entry.tools_run?.length > 0 && (
                      <div className="mt-1 truncate text-xs text-muted-foreground">
                        Scanned with: {entry.tools_run.join(", ")}
                      </div>
                    )}
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <Badge variant="outline" className={LOG_STATUS_COLOR[entry.status] || "text-muted-foreground"}>
                      {entry.status}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {entry.new_findings_count} new finding{entry.new_findings_count === 1 ? "" : "s"}
                      {entry.highest_new_severity ? ` · highest: ${entry.highest_new_severity}` : ""}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {entry.new_endpoints_count} new endpoint{entry.new_endpoints_count === 1 ? "" : "s"}
                    </span>
                  </div>
                </button>

                {entry.status === "blocked" && (
                  <div className="mt-2">
                    <OverrideAction entry={entry} onOverridden={refresh} />
                  </div>
                )}

                {isExpanded && (
                  <div className="mt-3 border-t border-border pt-3">
                    <ScanFindings scanId={entry.id} />
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
        {!loading && log.length === 0 && (
          <EmptyState
            icon={ShieldQuestion}
            title="No PR Guardrail scans yet"
            description={isOrgWide ? "Across your repositories." : "For this target."}
            bare
          />
        )}
      </div>
      )}
    </div>
  );
}
