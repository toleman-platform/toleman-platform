"use client";

import { useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Finding, Target, api } from "@/lib/api";
import { FindingRow } from "@/components/finding-row";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination } from "@/components/activity-pagination";

const BULK_TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix", "Open"];

export function FindingsList({
  findings,
  total,
  page,
  pageSize,
  targets = [],
}: {
  findings: Finding[];
  total: number;
  page: number;
  pageSize: number;
  targets?: Target[];
}) {
  const repoUrlByTargetId = new Map(targets.map((t) => [t.id, t.repo_url]));
  // Issue #117: criticality chip + target name shown next to each finding's
  // target -- see Target.label in backend/app/models/models.py.
  const targetById = new Map(targets.map((t) => [t.id, t]));
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const allSelected = findings.length > 0 && findings.every((f) => selected.has(f.id));

  function toggleOne(id: number, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleAll(checked: boolean) {
    setSelected(checked ? new Set(findings.map((f) => f.id)) : new Set());
  }

  async function bulkTriage(toState: string) {
    if (selected.size === 0) return;
    setSubmitting(true);
    try {
      await api.bulkTriage(Array.from(selected), toState, reason);
      setSelected(new Set());
      setReason("");
      router.refresh();
    } finally {
      setSubmitting(false);
    }
  }

  function goToPage(nextPage: number) {
    const params = new URLSearchParams(searchParams.toString());
    params.set("page", String(nextPage));
    router.push(`${pathname}?${params.toString()}`);
  }

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / pageSize)), [total, pageSize]);
  const rangeStart = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const rangeEnd = Math.min(page * pageSize, total);

  return (
    <div className="flex flex-col gap-3">
      {findings.length > 0 && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <input
            type="checkbox"
            aria-label="Select all findings on this page"
            className="h-4 w-4 accent-primary"
            checked={allSelected}
            onChange={(e) => toggleAll(e.target.checked)}
          />
          <span>Select all on this page</span>
        </div>
      )}

      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-secondary/50 p-3">
          <span className="text-xs font-medium text-foreground">{selected.size} selected:</span>
          <Input
            className="h-7 min-w-[160px] flex-1 bg-secondary text-xs"
            placeholder="Reason (applies to all selected)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          {BULK_TRIAGE_STATES.map((s) => (
            <Button key={s} size="sm" variant="outline" disabled={submitting} onClick={() => bulkTriage(s)} className="h-7 text-xs">
              {s}
            </Button>
          ))}
          <button onClick={() => setSelected(new Set())} className="text-xs text-muted-foreground underline">
            clear selection
          </button>
        </div>
      )}

      {total > pageSize && <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />}

      {/* gap tracks density too (#172) -- 25 rows of an 8px gap is another
          200px of scroll on a page whose whole point is scanning a list. */}
      <div className="flex flex-col" style={{ gap: "var(--density-list-gap)" }}>
        {findings.map((f) => (
          <FindingRow
            key={f.id}
            finding={f}
            repoUrl={repoUrlByTargetId.get(f.target_id)}
            targetName={targetById.get(f.target_id)?.name}
            targetLabel={targetById.get(f.target_id)?.label}
            selectable
            selected={selected.has(f.id)}
            onSelectChange={(checked) => toggleOne(f.id, checked)}
          />
        ))}
        {findings.length === 0 && (
          <EmptyState
            icon={ShieldCheck}
            title={searchParams.toString() ? "No findings match these filters" : "No findings yet"}
            description={
              searchParams.toString()
                ? "Try widening your severity, tool, or state filters."
                : "Once a scan runs against your targets, findings will show up here."
            }
            action={
              searchParams.toString() ? (
                <Button size="sm" variant="outline" onClick={() => router.push(pathname)}>
                  Clear filters
                </Button>
              ) : (
                <Button size="sm" onClick={() => router.push("/scans")}>
                  Run a scan
                </Button>
              )
            }
          />
        )}
      </div>

      {/* Footer pager, now the shared component rather than a hand-rolled
          copy of it -- the top one above states the result-set size before
          the reader scrolls 3700px looking for it. */}
      {total > 0 && <ActivityPagination total={total} page={page} pageSize={pageSize} />}
    </div>
  );
}
