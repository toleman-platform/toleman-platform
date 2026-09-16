import { cookies } from "next/headers";
import { api } from "@/lib/api";
import { SCAN_TOOLS } from "@/lib/scan-tools";
import { WORKSPACE_COOKIE_KEY, parseWorkspaceCookie } from "@/lib/workspace-cookie";
import { ScansFilterBar } from "@/components/features/scans";
import { ScansList } from "./scans-list";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { PageHeader } from "@/components/ui/page-header";
import { settleOrNull, settledOr } from "@/std-lib";

// Issue #120: rebuild of the flat, unfiltered ~165-button scan-trigger grid
// (33 targets x 5 tools each) into the same search/filter/multi-select
// pattern Findings and Targets already established, plus #117's
// CriticalityChip and a Prod-aware confirmation step; see scans-list.tsx
// and components/scans-filter-bar.tsx for the actual behavior.
export default async function OnDemandScanPage() {
  // (#506) The global workspace switcher's active workspace, read from the
  // cookie WorkspaceContext keeps in sync -- see lib/workspace-cookie.ts.
  const workspace_id = parseWorkspaceCookie((await cookies()).get(WORKSPACE_COOKIE_KEY)?.value) ?? undefined;
  const [targetsResult, summarySettled] = await Promise.all([
    settleOrNull(api.targets({ workspace_id })),
    // `settledOr` rather than `?? {}`: an empty scan summary is not a fact
    // about the estate. This line used to discard the failure, and every row
    // below then evaluated `entry?.last_scan_at ? ... : "never scanned"`
    // against an empty map — so a single failed request told a security
    // operator that nothing in the estate had ever been scanned, with nothing
    // anywhere on the page indicating that something had gone wrong.
    settledOr(api.scanSummary(workspace_id), {}),
  ]);
  const targetsFailed = targetsResult === null;
  const targets = targetsResult ?? [];
  const [summary, summaryFailed] = summarySettled;

  // Tool filter options: the known on-demand tool set plus anything else
  // real scan history has recorded (e.g. checkov/tfsec run via other
  // surfaces but still visible in a target's history here), real data,
  // not a hardcoded guess of what's actually been run.
  const toolsFromHistory = new Set<string>(SCAN_TOOLS);
  for (const entry of Object.values(summary)) {
    for (const t of entry.tools) toolsFromHistory.add(t);
  }
  const tools = Array.from(toolsFromHistory).sort();

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="On-Demand Scan"
        description={`Trigger a native scan against any target · ${targets.length} target${targets.length === 1 ? "" : "s"}`}
      />

      <ScansFilterBar tools={tools} />

      {targetsFailed ? (
        <ErrorState
          description="The target list couldn't be loaded from the API."
          action={<ReloadButton />}
        />
      ) : (
        <ScansList targets={targets} summary={summary} summaryFailed={summaryFailed} />
      )}
    </div>
  );
}
