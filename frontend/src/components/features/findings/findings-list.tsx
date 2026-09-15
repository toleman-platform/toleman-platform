"use client";

import { useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Finding, Target, api } from "@/lib/api";
import { FindingRow } from "./finding-row";
import { FindingDetailDrawer } from "./finding-detail-drawer";
import { AlertBanner } from "@/components/ui/alert-banner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination } from "@/components/ui/activity-pagination";
import { BulkActionBar } from "@/components/ui/bulk-action-bar";
import { SelectAllVisible } from "@/components/ui/list-row";
import { useSelection } from "@/hooks/use-selection";
import { useWriteAction } from "@/hooks/use-write-action";

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
  const [inspectingFinding, setInspectingFinding] = useState<Finding | null>(null);
  // A bulk triage moves every selected finding in one request, so this is the
  // single most expensive write on the page to lose silently: 40 findings
  // selected, a rationale typed, the request rejects, the buttons re-enable
  // and the selection stays exactly as it was — indistinguishable from a
  // success whose list has not refreshed yet. See use-write-action.ts.
  const bulkAction = useWriteAction("Bulk triage failed");
  const submitting = bulkAction.submitting;

  // Issue #210: selection state now comes from useSelection, which is page-
  // aware by construction. The hand-rolled version here computed "select all"
  // against the rendered array, which was correct only because this list is
  // server-paginated; the same code in targets-list was not, and silently
  // selected rows the user could not see (#204).
  const visibleIds = useMemo(() => findings.map((f) => f.id), [findings]);
  const selection = useSelection(visibleIds);

  // The risk score is severity x target criticality x 40, so one target at one
  // criticality collapses it to a constant -- every row reading 320/1000, in
  // the highest-value corner of the row. Rather than drop the column or keep
  // showing a constant, it is hidden exactly when it has nothing to
  // distinguish, and the finding's age takes the space instead. Scoped to the
  // rows on screen because that is the comparison a reader is actually making.
  const scoreVaries = useMemo(
    () => new Set(findings.map((f) => f.priority_score)).size > 1,
    [findings],
  );

  async function bulkTriage(toState: string) {
    if (selection.count === 0) return;
    await bulkAction.run(async () => {
      await api.bulkTriage(selection.selectedIds, toState, reason);
      // Deliberately after the await: on failure the selection and the typed
      // rationale survive, so retrying is one click rather than reselecting
      // forty rows. Clearing them on failure would also have read as "done".
      selection.clear();
      setReason("");
      router.refresh();
    });
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

      {/* Outside the BulkActionBar rather than inside it: the bar is
          selection-gated, and the whole point of leaving the selection intact
          on failure is that this message and the retry it explains stay
          together. `AlertBanner` is `role="alert"`, so the failure is
          announced rather than only drawn. */}
      {bulkAction.error && (
        <AlertBanner tone="critical" title="Bulk triage failed">
          {/* Careful not to swap one false certainty for another: a rejected
              request may still have applied some or all of the changes before
              failing, so "no findings were changed" would be exactly the kind
              of unearned claim the rest of this page was just fixed for. What
              we can state is what the client knows — the call did not
              complete, and nothing here was cleared. */}
          {bulkAction.error} The change was not confirmed, so some findings may not have been
          updated. Your selection and rationale have been kept — reload to see the current
          states before retrying.
        </AlertBanner>
      )}

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
            showScore={scoreVaries}
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
