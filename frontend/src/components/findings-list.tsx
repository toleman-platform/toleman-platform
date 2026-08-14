"use client";

import { useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Finding, Target, api } from "@/lib/api";
import { FindingRow } from "@/components/finding-row";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/empty-state";

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

      <div className="flex flex-col gap-2">
        {findings.map((f) => (
          <FindingRow
            key={f.id}
            finding={f}
            repoUrl={repoUrlByTargetId.get(f.target_id)}
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

      {total > 0 && (
        <div className="flex items-center justify-between border-t border-border pt-3 text-xs text-muted-foreground">
          <span>
            Showing {rangeStart}-{rangeEnd} of {total}
          </span>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" className="h-7 text-xs" disabled={page <= 1} onClick={() => goToPage(page - 1)}>
              Previous
            </Button>
            <span>
              Page {page} of {totalPages}
            </span>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs"
              disabled={page >= totalPages}
              onClick={() => goToPage(page + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
