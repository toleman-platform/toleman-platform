"use client";

import { useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Finding, Target, api } from "@/lib/api";
import { FindingRow } from "./finding-row";
import { FindingDetailDrawer } from "./finding-detail-drawer";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination } from "@/components/activity-pagination";
import { BulkActionBar } from "@/components/ui/bulk-action-bar";
import { SelectAllVisible } from "@/components/ui/list-row";
import { useSelection } from "@/hooks/use-selection";

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
  // target; see Target.label in backend/app/models/models.py.
  const targetById = new Map(targets.map((t) => [t.id, t]));
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(null);

  // Issue #210: selection state now comes from useSelection, which is page-
  // aware by construction. The hand-rolled version here computed "select all"
  // against the rendered array, which was correct only because this list is
  // server-paginated; the same code in targets-list was not, and silently
  // selected rows the user could not see (#204).
  const visibleIds = useMemo(() => findings.map((f) => f.id), [findings]);
  const selection = useSelection(visibleIds);

  async function bulkTriage(toState: string) {
    if (selection.count === 0) return;
    setSubmitting(true);
    try {
      await api.bulkTriage(selection.selectedIds, toState, reason);
      selection.clear();
      setReason("");
      router.refresh();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      {findings.length > 0 && (
        <SelectAllVisible
          allSelected={selection.allVisibleSelected}
          someSelected={selection.someVisibleSelected}
          onChange={selection.toggleAllVisible}
        />
      )}

      <BulkActionBar
        count={selection.count}
        itemNoun="finding"
        onClear={selection.clear}
        actions={BULK_TRIAGE_STATES.map((s) => ({
          label: submitting ? "Updating..." : s,
          onClick: () => bulkTriage(s),
          destructive: s === "Won't Fix",
          disabled: submitting,
        }))}
      >
        <Input
          className="h-7 min-w-[200px] flex-1 bg-secondary text-xs"
          aria-label="Reason, applied to every selected finding"
          placeholder="Triage rationale / justification (applies to all selected)"
          value={reason}
          disabled={submitting}
          onChange={(e) => setReason(e.target.value)}
        />
      </BulkActionBar>

      {total > pageSize && <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />}

      {/* gap tracks density too (#172); 25 rows of an 8px gap is another
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
            selected={selection.isSelected(f.id)}
            onSelectChange={(checked) => selection.toggle(f.id, checked)}
            onInspect={(finding) => setInspectingFinding(finding)}
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

      {/* Master-Detail Quick Inspection Drawer (Section 14) */}
      <FindingDetailDrawer
        finding={inspectingFinding}
        repoUrl={inspectingFinding ? repoUrlByTargetId.get(inspectingFinding.target_id) : undefined}
        targetName={inspectingFinding ? targetById.get(inspectingFinding.target_id)?.name : undefined}
        onClose={() => setInspectingFinding(null)}
        onTriageSuccess={() => {
          router.refresh();
        }}
      />

      {/* Footer pager, now the shared component rather than a hand-rolled
          copy of it, the top one above states the result-set size before
          the reader scrolls 3700px looking for it. */}
      {total > 0 && <ActivityPagination total={total} page={page} pageSize={pageSize} />}
    </div>
  );
}
