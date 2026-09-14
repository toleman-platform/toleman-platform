"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { FindingGroup, Target } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination } from "@/components/activity-pagination";
import { FindingGroupRow } from "./finding-group-row";

/**
 * The findings list with one row per decision.
 *
 * Deliberately a plain table-like stack rather than the Card-per-row the flat
 * list uses: this view exists to be scanned, and a card's border, radius and
 * padding all say "separate object" on a page where the point is comparing
 * rows against each other.
 */
export function FindingsGroupsList({
  groups,
  total,
  totalFindings,
  page,
  pageSize,
  targets = [],
}: {
  groups: FindingGroup[];
  total: number;
  totalFindings: number;
  page: number;
  pageSize: number;
  targets?: Target[];
}) {
  const router = useRouter();
  const searchParams = useSearchParams();

  if (groups.length === 0) {
    return (
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
            <Button size="sm" variant="outline" onClick={() => router.push("/findings")}>
              Clear filters
            </Button>
          ) : (
            <Button size="sm" onClick={() => router.push("/scans")}>
              Run a scan
            </Button>
          )
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {/* Both numbers, always. A grouped count on its own reads as findings
          having been dropped rather than collapsed. */}
      <p className="text-xs text-muted-foreground">
        <span className="font-medium text-foreground">{total}</span> {total === 1 ? "decision" : "decisions"} across{" "}
        <span className="font-medium text-foreground">{totalFindings}</span>{" "}
        {totalFindings === 1 ? "finding" : "findings"}
      </p>

      {total > pageSize && <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />}

      <div className="overflow-hidden rounded-md border border-border">
        <div className="flex items-center gap-3 border-b border-border bg-secondary/60 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          <span className="w-3.5 shrink-0" aria-hidden="true" />
          <span className="w-[72px] shrink-0">Severity</span>
          <span className="min-w-0 flex-1">Subject</span>
          <span className="shrink-0">Findings</span>
          <span className="hidden shrink-0 md:block">Signals</span>
          <span className="hidden w-12 shrink-0 text-right lg:block">Oldest</span>
        </div>

        {groups.map((group) => (
          <FindingGroupRow
            key={`${group.tool}::${group.rule_id}`}
            group={group}
            targets={targets}
            onTriaged={() => router.refresh()}
          />
        ))}
      </div>

      {total > 0 && <ActivityPagination total={total} page={page} pageSize={pageSize} />}
    </div>
  );
}
