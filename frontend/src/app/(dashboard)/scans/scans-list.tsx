"use client";

import { useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Target, ScanSummary, api } from "@/lib/api";
import { SCAN_TOOLS } from "@/lib/scan-tools";
import { timeAgo } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CriticalityChip } from "@/components/features/targets";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination, pageSizeFromParams } from "@/components/activity-pagination";
import { ScanProgress } from "@/components/features/scans";
import { useActiveScans } from "@/hooks/features/use-active-scans";
import { BulkActionBar } from "@/components/ui/bulk-action-bar";
import { SelectAllVisible } from "@/components/ui/list-row";
import { useSelection } from "@/hooks/use-selection";
import { Scan as ScanIcon } from "lucide-react";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function paginateSlice<T>(items: T[], page: number, pageSize: number): { items: T[]; clampedPage: number } {
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const clampedPage = Math.min(Math.max(1, page), totalPages);
  const start = (clampedPage - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), clampedPage };
}

// A minimum spacing between dispatched POST /api/scans/run calls so a bulk
// trigger across several targets stays under the backend's per-user rate
// limit (10 requests / 60s, see backend/app/api/scans.py's
// SCAN_RUN_RATE_LIMIT) instead of hammering it and having later calls in
// the same batch 429.
const DISPATCH_SPACING_MS = 700;

const TOOL_SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

// "" means "all tools" (the pre-existing behavior: every tool the target has
// history for, falling back to the full default set). A specific value runs
// only that one tool instead of the whole sequence.
const ALL_TOOLS_VALUE = "";

// Dispatch outcome only. Whether the work is actually *running* now comes
// from GET /api/scans/active (useActiveScans) rather than being inferred
// here: the old "done" state was set the moment the POST returned, so a row
// claimed the scan was finished while the worker had not yet started it.
type DispatchState = "idle" | "dispatching" | "dispatched" | "error";

function lastScannedBucket(lastScanAt: string | null): string {
  if (!lastScanAt) return "never";
  const ageMs = Date.now() - new Date(lastScanAt).getTime();
  const day = 24 * 60 * 60 * 1000;
  if (ageMs <= day) return "24h";
  if (ageMs <= 7 * day) return "7d";
  if (ageMs <= 30 * day) return "30d";
  return "older";
}

// Issue #120: the old page was a flat grid of ~165 scan-trigger buttons (33
// targets x 5 tools each) with no search, filter, multi-select, or visual
// distinction between a throwaway Internal target and a Prod one. This
// rebuild reuses Findings' filter-bar convention (see scans-filter-bar.tsx),
// Targets' checkbox + bulk-action-bar multi-select pattern (see
// targets/targets-list.tsx), #117's CriticalityChip (reused verbatim, not
// re-implemented), and #118's ConfirmDialog for a Prod-aware confirmation
// step nothing on this surface had before.
export function ScansList({ targets, summary }: { targets: Target[]; summary: ScanSummary }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [dispatchState, setDispatchState] = useState<Record<number, DispatchState>>({});
  const { activeScans, isTargetScanning, refresh: refreshActiveScans } = useActiveScans();
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [confirmIds, setConfirmIds] = useState<number[] | null>(null);
  const [confirmTool, setConfirmTool] = useState<string>(ALL_TOOLS_VALUE);
  const [confirming, setConfirming] = useState(false);
  // Per-row tool choice, keyed by target id; unset entries default to "all
  // tools". Kept separate from the bulk-bar choice below so picking a tool
  // for one row doesn't affect what a multi-select scan runs.
  const [rowTool, setRowTool] = useState<Record<number, string>>({});
  const [bulkTool, setBulkTool] = useState<string>(ALL_TOOLS_VALUE);

  const search = (searchParams.get("search") ?? "").trim().toLowerCase();
  const criticality = searchParams.get("criticality") ?? "";
  const tool = searchParams.get("tool") ?? "";
  const lastScanned = searchParams.get("last_scanned") ?? "";
  const page = Math.max(1, Number(searchParams.get("page") ?? "1") || 1);
  const pageSize = pageSizeFromParams(searchParams.get("page_size") ?? undefined);

  const filtered = useMemo(() => {
    return targets.filter((t) => {
      if (search) {
        const haystack = `${t.name} ${t.repo_url}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      if (criticality && t.label !== criticality) return false;
      const entry = summary[String(t.id)];
      if (tool && !(entry?.tools ?? []).includes(tool)) return false;
      if (lastScanned && lastScannedBucket(entry?.last_scan_at ?? null) !== lastScanned) return false;
      return true;
    });
  }, [targets, summary, search, criticality, tool, lastScanned]);

  const { items: visible, clampedPage } = paginateSlice(filtered, page, pageSize);
  const visibleIds = useMemo(() => visible.map((t) => t.id), [visible]);
  const selection = useSelection(visibleIds);

  // "Scan" re-runs whichever on-demand-triggerable tools this target has
  // real history for, falling back to the full default set for a
  // never-scanned target. History can also contain tools that only exist
  // via CI/webhook ingestion (not runnable through POST /api/scans/run;
  // see backend/app/scanners/parsers.PARSER_MAP); those are filtered out
  // here rather than dispatched into a guaranteed "unsupported tool" error.
  function toolsForTarget(id: number): readonly string[] {
    const known = (summary[String(id)]?.tools ?? []).filter((t) => (SCAN_TOOLS as readonly string[]).includes(t));
    return known.length > 0 ? known : SCAN_TOOLS;
  }

  // tool === ALL_TOOLS_VALUE keeps the original "every known tool for this
  // target" behavior; a specific tool dispatches only that one.
  async function runScansFor(ids: number[], tool: string) {
    setScanMessage(null);
    setDispatchState((prev) => {
      const next = { ...prev };
      for (const id of ids) next[id] = "dispatching";
      return next;
    });

    let dispatched = 0;
    let failed = 0;
    for (const id of ids) {
      let targetFailed = false;
      const toolsToRun = tool === ALL_TOOLS_VALUE ? toolsForTarget(id) : [tool];
      for (const t of toolsToRun) {
        try {
          const res = await api.runScan(id, t);
          if ("error" in res) {
            targetFailed = true;
          } else {
            dispatched += 1;
          }
        } catch {
          targetFailed = true;
        }
        await sleep(DISPATCH_SPACING_MS);
      }
      setDispatchState((prev) => ({ ...prev, [id]: targetFailed ? "error" : "dispatched" }));
      if (targetFailed) failed += 1;
      // Flip the row to its real running state now rather than waiting out
      // the poll interval.
      refreshActiveScans();
    }

    setScanMessage(
      failed > 0
        ? `Dispatched ${dispatched} scan${dispatched === 1 ? "" : "s"} · ${failed} target${failed === 1 ? "" : "s"} hit an error (rate limit or scan failure); check Scan History.`
        : `Dispatched ${dispatched} scan${dispatched === 1 ? "" : "s"} across ${ids.length} target${ids.length === 1 ? "" : "s"}. Progress is shown on each row below.`
    );
    selection.clear();
    router.refresh();
  }

  function requestScan(ids: number[], tool: string) {
    const prodIds = ids.filter((id) => targets.find((t) => t.id === id)?.label === "Prod");
    if (prodIds.length > 0) {
      setConfirmIds(ids);
      setConfirmTool(tool);
    } else {
      void runScansFor(ids, tool);
    }
  }

  async function confirmScan() {
    if (!confirmIds) return;
    setConfirming(true);
    try {
      await runScansFor(confirmIds, confirmTool);
    } finally {
      setConfirming(false);
      setConfirmIds(null);
    }
  }

  const confirmTargets = confirmIds ? targets.filter((t) => confirmIds.includes(t.id)) : [];
  const confirmProdCount = confirmTargets.filter((t) => t.label === "Prod").length;

  const selectedTargets = useMemo(() => targets.filter((t) => selection.isSelected(t.id)), [targets, selection]);
  const selectedProdCount = useMemo(() => selectedTargets.filter((t) => t.label === "Prod").length, [selectedTargets]);

  if (targets.length === 0) {
    return (
      <EmptyState
        icon={ScanIcon}
        title="No targets yet"
        description="Add a repository in Targets before you can trigger a scan."
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {filtered.length > 0 && (
        <SelectAllVisible
          allSelected={selection.allVisibleSelected}
          someSelected={selection.someVisibleSelected}
          onChange={selection.toggleAllVisible}
        />
      )}

      <BulkActionBar
        count={selection.count}
        itemNoun="target"
        onClear={selection.clear}
        actions={[
          {
            label: selectedProdCount > 0 ? "Scan Selected (Prod)..." : "Scan Selected",
            onClick: () => requestScan(selection.selectedIds, bulkTool),
            destructive: selectedProdCount > 0,
          },
        ]}
      >
        <select
          aria-label="Tool to run on selected targets"
          className={TOOL_SELECT_CLASS}
          value={bulkTool}
          onChange={(e) => setBulkTool(e.target.value)}
        >
          <option value={ALL_TOOLS_VALUE}>All tools</option>
          {SCAN_TOOLS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        {selectedProdCount > 0 && (
          <span className="text-xs font-medium text-destructive">
            {selectedProdCount} Prod target{selectedProdCount === 1 ? "" : "s"} included
          </span>
        )}
      </BulkActionBar>

      {scanMessage && <p className="text-xs text-muted-foreground">{scanMessage}</p>}

      {filtered.length === 0 ? (
        <EmptyState
          icon={ScanIcon}
          title="No targets match these filters"
          description="Try clearing search, criticality, tool, or last-scanned filters."
        />
      ) : (
        <>
        <ActivityPagination total={filtered.length} page={clampedPage} pageSize={pageSize} position="top" />
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {visible.map((t) => {
            const entry = summary[String(t.id)];
            const state = dispatchState[t.id] ?? "idle";
            const running = activeScans[String(t.id)] ?? [];
            const scanning = isTargetScanning(t.id);
            // Disabled while dispatching or while work is genuinely in
            // flight, so a second click cannot queue a duplicate scan.
            const busy = state === "dispatching" || scanning;
            return (
              <Card
                key={t.id}
                className={
                  selection.isSelected(t.id)
                    ? "border-accent-strong/40 bg-accent/5"
                    : "border-border bg-card"
                }
              >
                <CardContent className="flex items-center gap-3 px-4 py-3">
                  <input
                    type="checkbox"
                    aria-label={`Select ${t.name}`}
                    className="h-4 w-4 shrink-0 accent-primary"
                    checked={selection.isSelected(t.id)}
                    onChange={(e) => selection.toggle(t.id, e.target.checked)}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium text-foreground">{t.name}</span>
                      <CriticalityChip label={t.label} />
                    </div>
                    <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                      {t.default_branch} ·{" "}
                      {entry?.last_scan_at ? `last scan ${timeAgo(entry.last_scan_at)}` : "never scanned"}
                      {entry && entry.tools.length > 0 ? ` · ${entry.tools.join(", ")}` : ""}
                    </div>
                    {scanning && (
                      <div className="mt-1.5 flex flex-col gap-1">
                        {running.map((scan) => (
                          <ScanProgress
                            key={scan.scan_id}
                            phase="running"
                            tool={scan.tool}
                            elapsedSeconds={scan.elapsed_seconds}
                            etaSeconds={scan.eta_seconds}
                          />
                        ))}
                      </div>
                    )}
                    {!scanning && state === "dispatching" && (
                      <div className="mt-1.5">
                        <ScanProgress phase="queued" />
                      </div>
                    )}
                  </div>
                  {/* Issue #171: this used to be `destructive` on Prod rows,
                      which painted roughly half the page solid red for what
                      is a read-only action. The Prod signal is already
                      carried twice (by the red CriticalityChip above and by
                      the Prod-aware ConfirmDialog below) so the third copy
                      only diluted what `destructive` means everywhere else in
                      the app. The bulk-action button keeps the destructive
                      variant: one click there fires N scans at once. */}
                  <div className="flex shrink-0 items-center gap-1.5">
                    <select
                      aria-label={`Tool to run on ${t.name}`}
                      className={TOOL_SELECT_CLASS}
                      disabled={busy}
                      value={rowTool[t.id] ?? ALL_TOOLS_VALUE}
                      onChange={(e) => setRowTool((prev) => ({ ...prev, [t.id]: e.target.value }))}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <option value={ALL_TOOLS_VALUE}>All tools</option>
                      {toolsForTarget(t.id).map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 text-xs"
                      disabled={busy}
                      onClick={() => requestScan([t.id], rowTool[t.id] ?? ALL_TOOLS_VALUE)}
                    >
                      {busy ? "Scanning..." : state === "dispatched" ? "Scan again" : "Scan"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
        {filtered.length > pageSize && (
          <ActivityPagination total={filtered.length} page={clampedPage} pageSize={pageSize} />
        )}
        </>
      )}

      <ConfirmDialog
        open={confirmIds !== null}
        title={`Scan includes ${confirmProdCount} Prod target${confirmProdCount === 1 ? "" : "s"}`}
        description={
          <>
            You&apos;re about to trigger a native{confirmTool !== ALL_TOOLS_VALUE ? ` ${confirmTool}` : ""} scan
            against{" "}
            {confirmTargets.map((t, i) => (
              <span key={t.id}>
                {i > 0 && (i === confirmTargets.length - 1 ? " and " : ", ")}
                <span className="font-medium text-foreground">{t.name}</span>{" "}
                <CriticalityChip label={t.label} className="align-middle" />
              </span>
            ))}
            . Prod scans run against the live default branch and count against each target&apos;s scan-rate limit.
          </>
        }
        confirmLabel={confirmIds ? `Scan ${confirmIds.length} target${confirmIds.length === 1 ? "" : "s"}` : "Scan"}
        tone="destructive"
        loading={confirming}
        onConfirm={confirmScan}
        onCancel={() => setConfirmIds(null)}
      />
    </div>
  );
}
