"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Finding, FindingGroup, FindingsQuery, Target } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination } from "@/components/activity-pagination";
import { FindingGroupRow } from "./finding-group-row";
import { FindingDetailDrawer } from "./finding-detail-drawer";

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
  truncated = false,
  page,
  pageSize,
  memberQuery,
  targets = [],
}: {
  groups: FindingGroup[];
  total: number;
  totalFindings: number;
  /** The group set hit the server's ceiling, so the counts below are floors. */
  truncated?: boolean;
  page: number;
  pageSize: number;
  /** The filters this list was built with, handed to each row so its members match its count. */
  memberQuery?: FindingsQuery;
  targets?: Target[];
}) {
  const router = useRouter();
  const searchParams = useSearchParams();
  // One drawer for the whole list rather than one per row, the same shape
  // findings-list.tsx uses: the grouped row collapsed the page to what a
  // decision needs, and this is the way back to what a single finding needs.
  const [inspecting, setInspecting] = useState<Finding | null>(null);
  const repoUrlByTargetId = new Map(targets.map((t) => [t.id, t.repo_url]));
  const targetById = new Map(targets.map((t) => [t.id, t]));

  return (
    <div className="flex flex-col gap-3">
      {/* Both numbers, always. A grouped count on its own reads as findings
          having been dropped rather than collapsed. */}
      <p className="text-xs text-muted-foreground">
        <span className="font-medium text-foreground">{total}</span> {total === 1 ? "decision" : "decisions"} across{" "}
        <span className="font-medium text-foreground">{totalFindings}</span>{" "}
        {totalFindings === 1 ? "finding" : "findings"}
      </p>

      {truncated && (
        <p className="text-xs text-destructive">
          Showing the first {total} groups. Narrow the filters for exact counts.
        </p>
      )}

      {total > pageSize && <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />}

      {/* EmptyState renders inside the list rather than replacing it, so
          overshooting the last page still shows the pager that gets you back
          — the same shape findings-list.tsx uses. Returning early here meant
          `?page=9` of a 3-page result read as "no findings match". */}
      {groups.length === 0 ? (
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
      ) : (
        // core M11: real table semantics -- `table`/`rowgroup`/`row`/
        // `columnheader`/`cell` -- laid over the same flex/div structure
        // rather than a native <table>, because a native table's cell model
        // (fixed column widths, no `shrink`/`hidden md:block` responsive
        // collapse) is incompatible with the row staying one line at every
        // density. This is the standard "CSS table" ARIA pattern for exactly
        // that situation: a screen reader gets row/column navigation and each
        // cell announced against its header, and the visual layout is
        // unchanged. See FindingGroupRow for the per-row half of this fix.
        <div role="table" aria-label="Grouped findings" className="overflow-hidden rounded-md border border-border">
          <div role="rowgroup">
            <div role="row" className="flex items-center gap-3 border-b border-border bg-secondary/60 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <span role="columnheader" aria-label="Expand" className="w-3.5 shrink-0" />
              <span role="columnheader" className="w-[72px] shrink-0">Severity</span>
              <span role="columnheader" className="min-w-0 flex-1">Subject</span>
              <span role="columnheader" className="shrink-0">Findings</span>
              <span role="columnheader" className="hidden shrink-0 md:block">Signals</span>
              <span role="columnheader" className="hidden w-12 shrink-0 text-right lg:block">Oldest</span>
            </div>
          </div>

          <div role="rowgroup">
            {groups.map((group) => (
              <FindingGroupRow
                // representative_id, not (tool, rule_id): the ungrouped half emits
                // one row per finding, so several rows can share a tool and rule
                // and React would see duplicate keys — warning, and misassociating
                // each row's expand/members/reason state on reorder.
                key={group.representative_id}
                group={group}
                memberQuery={memberQuery}
                targets={targets}
                onTriaged={() => router.refresh()}
                onInspect={setInspecting}
              />
            ))}
          </div>
        </div>
      )}

      {total > 0 && <ActivityPagination total={total} page={page} pageSize={pageSize} />}

      <FindingDetailDrawer
        finding={inspecting}
        repoUrl={inspecting ? repoUrlByTargetId.get(inspecting.target_id) : undefined}
        targetName={inspecting ? targetById.get(inspecting.target_id)?.name : undefined}
        onClose={() => setInspecting(null)}
        onTriageSuccess={() => router.refresh()}
      />
    </div>
  );
}
