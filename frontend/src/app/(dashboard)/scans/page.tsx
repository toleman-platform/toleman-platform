import { api } from "@/lib/api";
import { SCAN_TOOLS } from "@/lib/scan-tools";
import { ScansFilterBar } from "@/components/scans-filter-bar";
import { ScansList } from "./scans-list";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { settleOrNull } from "@/lib/settle";

// Issue #120: rebuild of the flat, unfiltered ~165-button scan-trigger grid
// (33 targets x 5 tools each) into the same search/filter/multi-select
// pattern Findings and Targets already established, plus #117's
// CriticalityChip and a Prod-aware confirmation step -- see scans-list.tsx
// and components/scans-filter-bar.tsx for the actual behavior.
export default async function OnDemandScanPage() {
  const [targetsResult, summaryResult] = await Promise.all([
    settleOrNull(api.targets()),
    settleOrNull(api.scanSummary()),
  ]);
  const targetsFailed = targetsResult === null;
  const targets = targetsResult ?? [];
  const summary = summaryResult ?? {};

  // Tool filter options: the known on-demand tool set plus anything else
  // real scan history has recorded (e.g. checkov/tfsec run via other
  // surfaces but still visible in a target's history here) -- real data,
  // not a hardcoded guess of what's actually been run.
  const toolsFromHistory = new Set<string>(SCAN_TOOLS);
  for (const entry of Object.values(summary)) {
    for (const t of entry.tools) toolsFromHistory.add(t);
  }
  const tools = Array.from(toolsFromHistory).sort();

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">On-Demand Scan</h1>
        <p className="text-sm text-muted-foreground">
          Trigger a native scan against any target · {targets.length} target{targets.length === 1 ? "" : "s"}
        </p>
      </div>

      <ScansFilterBar tools={tools} />

      {targetsFailed ? (
        <ErrorState
          description="The target list couldn't be loaded from the API."
          action={<ReloadButton />}
        />
      ) : (
        <ScansList targets={targets} summary={summary} />
      )}
    </div>
  );
}
