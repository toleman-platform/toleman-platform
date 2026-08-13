"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { PipelineIntegrationBatch, Target, api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { GroupBadge } from "@/components/group-badge";
import { pollUntilSettled } from "@/lib/poll";

const ITEM_STATUS_LABEL: Record<string, string> = {
  pending: "Queued",
  running: "Opening PR...",
  succeeded: "PR opened",
  failed: "Failed",
  already_integrated: "Already integrated",
};

function itemBadgeClass(status: string): string {
  switch (status) {
    case "succeeded":
      return "border-green-600/40 text-green-500";
    case "already_integrated":
      return "border-blue-600/40 text-blue-400";
    case "failed":
      return "border-red-600/40 text-red-500";
    case "running":
      return "border-amber-600/40 text-amber-400";
    default:
      return "text-muted-foreground";
  }
}

// Issue #68: multi-select wrapper around #66's per-target "Add Pipeline"
// mechanism (see targets/[id]/pipeline-integration.tsx). Checkbox selection
// + bulk action bar UX follows the established pattern in
// components/findings-list.tsx (findings' bulk-triage bar) rather than
// inventing a new one.
export function TargetsList({ targets }: { targets: Target[] }) {
  const router = useRouter();
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [batch, setBatch] = useState<PipelineIntegrationBatch | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);

  useEffect(() => {
    if (!batch || batch.status !== "running") return;
    const cancel = pollUntilSettled(
      () => api.getPipelineIntegrationBatch(batch.batch_id),
      (result) => setBatch(result),
      { onError: (err) => setBatchError(err instanceof Error ? err.message : "failed to poll batch status") }
    );
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch?.batch_id]);

  function toggleOne(id: number, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleAll(checked: boolean) {
    setSelected(checked ? new Set(targets.map((t) => t.id)) : new Set());
  }

  async function addPipelineBulk() {
    if (selected.size === 0) return;
    setSubmitting(true);
    setBatchError(null);
    try {
      const res = await api.bulkPipelineIntegrate(Array.from(selected));
      setBatch({
        batch_id: res.batch_id,
        status: res.status,
        total: res.total,
        succeeded: 0,
        failed: 0,
        already_integrated: 0,
        started_at: new Date().toISOString(),
        completed_at: null,
        items: [],
      });
      setSelected(new Set());
    } catch (e) {
      setBatchError(e instanceof Error ? e.message : "failed to start bulk pipeline integration");
    } finally {
      setSubmitting(false);
    }
  }

  function closeBatchPanel() {
    setBatch(null);
    setBatchError(null);
    if (batch?.status === "completed") router.refresh();
  }

  const allSelected = targets.length > 0 && targets.every((t) => selected.has(t.id));

  return (
    <div className="flex flex-col gap-2">
      {targets.length > 0 && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <input
            type="checkbox"
            aria-label="Select all targets"
            className="h-4 w-4 accent-primary"
            checked={allSelected}
            onChange={(e) => toggleAll(e.target.checked)}
          />
          <span>Select all</span>
        </div>
      )}

      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-secondary/50 p-3">
          <span className="text-xs font-medium text-foreground">{selected.size} selected</span>
          <Button size="sm" disabled={submitting} onClick={addPipelineBulk} className="h-7 text-xs">
            {submitting ? "Starting..." : `Add Pipeline to ${selected.size} repo${selected.size === 1 ? "" : "s"}`}
          </Button>
          <button onClick={() => setSelected(new Set())} className="text-xs text-muted-foreground underline">
            clear selection
          </button>
        </div>
      )}

      {batchError && <p className="text-xs text-destructive">{batchError}</p>}

      {batch && (
        <div className="flex flex-col gap-2 rounded-md border border-border bg-card p-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-foreground">
              {batch.status === "running" ? (
                <>Adding pipeline to {batch.total} repos...</>
              ) : (
                <>
                  Done: {batch.succeeded} succeeded, {batch.already_integrated} already integrated, {batch.failed}{" "}
                  failed
                </>
              )}
            </div>
            <button onClick={closeBatchPanel} className="text-xs text-muted-foreground underline">
              {batch.status === "running" ? "hide" : "close"}
            </button>
          </div>
          {batch.items.length > 0 && (
            <ul className="flex flex-col gap-1">
              {batch.items.map((item) => (
                <li key={item.target_id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-foreground">{item.target_name ?? `target #${item.target_id}`}</span>
                  <div className="flex items-center gap-2">
                    {item.status === "failed" && item.error && (
                      <span className="max-w-xs truncate text-destructive" title={item.error}>
                        {item.error}
                      </span>
                    )}
                    {item.pr_url && (
                      <a href={item.pr_url} target="_blank" rel="noreferrer" className="text-primary underline underline-offset-2">
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
            <p className="text-xs text-muted-foreground">Starting...</p>
          )}
        </div>
      )}

      {targets.map((t) => (
        <Card key={t.id} className="border-border bg-card transition-colors hover:border-primary/40">
          <CardContent className="flex items-center gap-3 px-4 py-3">
            <input
              type="checkbox"
              aria-label={`Select ${t.name}`}
              className="h-4 w-4 shrink-0 accent-primary"
              checked={selected.has(t.id)}
              onChange={(e) => toggleOne(t.id, e.target.checked)}
              onClick={(e) => e.stopPropagation()}
            />
            <Link href={`/targets/${t.id}`} className="flex flex-1 items-center justify-between">
              <div>
                <div className="font-medium text-foreground">{t.name}</div>
                <div className="text-xs text-muted-foreground">{t.repo_url}</div>
                {t.groups.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {t.groups.map((g) => (
                      <GroupBadge key={g.id} group={g} />
                    ))}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                {t.pipeline_integrated && (
                  <Badge variant="outline" className="border-green-600/40 text-green-500">
                    Pipeline integrated
                  </Badge>
                )}
                <span className="text-xs text-muted-foreground">
                  {t.label} · weight {t.criticality_weight}
                </span>
              </div>
            </Link>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
