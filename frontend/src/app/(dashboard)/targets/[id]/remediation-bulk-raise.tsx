"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import type { RemediationPrBatch } from "@/types";
import { pollUntilSettled } from "@/lib/poll";
import { safeHref } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// (#247 follow-up) Bulk "Raise all": one Celery batch that opens a PR for
// every package currently in the fix plan, same async batch-then-poll
// shape as targets-list.tsx's bulk pipeline integration (pollUntilSettled
// against getRaiseAllFixPrsBatch), with a live per-package progress panel
// rather than a fire-and-forget toast, so a long-running batch over a
// large plan stays legible while it works.
const ITEM_STATUS_LABEL: Record<string, string> = {
  pending: "Queued",
  running: "Opening PR…",
  succeeded: "PR opened",
  failed: "Failed",
};

function itemBadgeClass(status: string): string {
  switch (status) {
    case "succeeded":
      return "border-chart-5/40 text-chart-5";
    case "failed":
      return "border-destructive/40 text-destructive";
    case "running":
      return "border-chart-3/40 text-chart-3";
    default:
      return "text-muted-foreground";
  }
}

export function RemediationBulkRaise({ targetId, totalPackages }: { targetId: number; totalPackages: number }) {
  const router = useRouter();
  const [batch, setBatch] = useState<RemediationPrBatch | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // "hide" (batch still running) must not throw away the only thing that
  // lets the panel be restored -- batch.batch_id -- or the still-running
  // job on the server becomes unreachable from this screen until reload.
  // Separate from `batch` itself so hiding never cancels the poll effect
  // below (which keys off batch?.batch_id).
  const [hidden, setHidden] = useState(false);
  // pollUntilSettled stops retrying after the first fetch error (see
  // lib/poll.ts) rather than backing off and trying again, so without this
  // a transient network blip leaves the panel stuck showing stale progress
  // forever even though the batch may have long since finished server-side.
  // Bumping this re-runs the poll effect (see its dependency array) so
  // "retry" genuinely resumes polling the same batch_id, not just clears
  // the message.
  const [pollError, setPollError] = useState<string | null>(null);
  const [pollAttempt, setPollAttempt] = useState(0);

  useEffect(() => {
    if (!batch || batch.status !== "running") return;
    const cancel = pollUntilSettled(
      () => api.getRaiseAllFixPrsBatch(batch.batch_id),
      (result) => setBatch(result),
      { onError: (err) => setPollError(err instanceof Error ? err.message : "failed to poll batch status") },
    );
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch?.batch_id, pollAttempt]);

  async function raiseAll() {
    setSubmitting(true);
    setError(null);
    setPollError(null);
    try {
      const res = await api.raiseAllFixPrs(targetId);
      setBatch({
        batch_id: res.batch_id,
        target_id: targetId,
        status: res.status as "running" | "completed",
        total: res.total,
        succeeded: 0,
        failed: 0,
        started_at: new Date().toISOString(),
        completed_at: null,
        items: [],
      });
      setHidden(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to start bulk raise");
    } finally {
      setSubmitting(false);
    }
  }

  function toggle() {
    if (batch?.status === "completed") {
      // Genuinely done: nothing left to poll, safe to discard.
      setBatch(null);
      setError(null);
      setPollError(null);
      setHidden(false);
      router.refresh();
      return;
    }
    // Still running: only collapse the panel. Polling (keyed off
    // batch?.batch_id, unaffected by `hidden`) keeps going in the
    // background, so progress isn't lost, and re-showing it doesn't need
    // a fresh "Raise all" click.
    setHidden((h) => !h);
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <Button
        size="sm"
        onClick={raiseAll}
        disabled={submitting || totalPackages === 0 || batch?.status === "running"}
      >
        {submitting ? "Starting…" : `Raise all (${totalPackages})`}
      </Button>
      {error && <p className="text-xs text-destructive">{error}</p>}

      {batch && hidden && (
        <button onClick={() => setHidden(false)} className="text-xs text-muted-foreground underline">
          {batch.status === "running"
            ? `Raising PRs for ${batch.total} package${batch.total === 1 ? "" : "s"}… (show)`
            : "Show results"}
        </button>
      )}

      {batch && !hidden && (
        <div className="flex w-full flex-col gap-2 rounded-md border border-border bg-card p-3 text-left">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-foreground">
              {batch.status === "running" ? (
                <>Raising PRs for {batch.total} package{batch.total === 1 ? "" : "s"}…</>
              ) : (
                <>Done: {batch.succeeded} succeeded, {batch.failed} failed</>
              )}
            </div>
            <button onClick={toggle} className="text-xs text-muted-foreground underline">
              {batch.status === "running" ? "hide" : "close"}
            </button>
          </div>
          {pollError && (
            <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-2">
              <p className="text-xs text-destructive">Lost touch with the batch: {pollError}</p>
              <button
                onClick={() => {
                  setPollError(null);
                  setPollAttempt((n) => n + 1);
                }}
                className="shrink-0 text-xs text-accent-strong underline underline-offset-2"
              >
                Retry
              </button>
            </div>
          )}
          {batch.items.length > 0 && (
            <ul className="flex flex-col gap-1">
              {batch.items.map((item) => (
                <li key={item.package} className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-code text-foreground">{item.package}</span>
                  <div className="flex items-center gap-2">
                    {item.status === "failed" && item.error && (
                      <span className="max-w-xs truncate text-destructive" title={item.error}>
                        {item.error}
                      </span>
                    )}
                    {item.pr_url && (
                      <a
                        href={safeHref(item.pr_url)}
                        target="_blank"
                        rel="noreferrer"
                        className="text-accent-strong underline underline-offset-2"
                      >
                        PR
                      </a>
                    )}
                    <Badge variant="outline" className={`text-[10px] ${itemBadgeClass(item.status)}`}>
                      {ITEM_STATUS_LABEL[item.status] ?? item.status}
                    </Badge>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {batch.status === "running" && batch.items.length === 0 && (
            <p className="text-xs text-muted-foreground">Starting…</p>
          )}
        </div>
      )}
    </div>
  );
}
