"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  Group,
  PipelineIntegrationBatch,
  PipelineWorkflowTemplate,
  ScanSummary,
  Target,
  TargetSummary,
  TargetSummaryEntry,
  WorkspaceSummary,
  api,
} from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useActiveScans } from "@/hooks/use-active-scans";
import { ScanProgress } from "@/components/scan-status";
import { safeHref, timeAgo } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { GroupBadge } from "@/components/group-badge";
import { CriticalityChip } from "@/components/criticality-chip";
import { EmptyState } from "@/components/ui/empty-state";
import { pollUntilSettled } from "@/lib/poll";
import { ActivityPagination, pageSizeFromParams } from "@/components/activity-pagination";
import type { TargetSort } from "./targets-filter-bar";
import { Rocket, X } from "lucide-react";
import { cn } from "@/lib/utils";

type QuickFilter = "all" | "attention" | "unscanned" | "stale";

const QUICK_FILTERS: { value: QuickFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "attention", label: "Needs attention" },
  { value: "unscanned", label: "Never scanned" },
  { value: "stale", label: "Stale (30d+)" },
];

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
      return "border-chart-5/40 text-chart-5";
    case "already_integrated":
      return "border-chart-2/40 text-chart-2";
    case "failed":
      return "border-destructive/40 text-destructive";
    case "running":
      return "border-chart-3/40 text-chart-3";
    default:
      return "text-muted-foreground";
  }
}

// Issue #117 / backend/app/core/scoring.py: criticality_weight is the 1-5
// multiplier a target contributes to every finding's risk score. The Repo
// Sync card used to render it as a bare "weight 2" with no label, no units
// and no tooltip, on every row -- unreadable as anything but a constant.
const CRITICALITY_WEIGHT_EXPLANATION =
  "How much this repo amplifies the risk score of its findings: severity × this weight × 40. " +
  "Set per target (1-5) alongside its criticality label.";

// Issue #185: AI/ML repo marker. The tooltip carries the detection signals
// because a bare badge isn't contestable -- someone who thinks the platform
// is wrong needs to see what it matched on. A manual override is labelled as
// such so "the platform detected this" and "a human forced this" stay
// distinguishable.
function AiRepoBadge({ target }: { target: Target }) {
  if (!target.is_ai_repo_effective) return null;
  const forced = target.is_ai_repo_override === true && !target.is_ai_repo;
  const title = forced
    ? "Marked as an AI/ML repo manually (auto-detection did not match)"
    : target.is_ai_repo_signals || "Detected as an AI/ML repo";
  return (
    <Badge
      variant="outline"
      title={title}
      className="shrink-0 border-chart-2/40 px-1.5 py-0 text-[10px] text-chart-2"
    >
      AI/ML{forced ? " (manual)" : ""}
    </Badge>
  );
}

// Open findings on the target's default branch (#174). Renders nothing at
// all when the summary is missing rather than a fabricated "0" -- a failed
// /api/targets/summary and a genuinely clean repo are different facts.
// github.com/org/repo.git -> org/repo. The full URL was the widest element
// on the card and the least informative -- it is kept as a title tooltip.
function repoSlug(repoUrl: string): string {
  return repoUrl
    .replace(/^https?:\/\/(www\.)?github\.com\//, "")
    .replace(/\.git$/, "")
    .replace(/\/$/, "");
}

// Scan age, coloured only when it is genuinely stale. A repo scanned today
// and one scanned last quarter read identically as plain grey text
// otherwise, which defeats the point of showing the date at all.
function ScanFreshness({ lastScanAt }: { lastScanAt: string | null }) {
  // Captured at mount rather than read during render: staleness is measured
  // in days, so re-reading the clock changes nothing visible, and a render
  // that depends on the current time is impure.
  const [now] = useState(() => Date.now());
  if (!lastScanAt) {
    return (
      <span className="text-chart-3" title="This repository has never been scanned">
        never scanned
      </span>
    );
  }
  const ageDays = (now - new Date(lastScanAt).getTime()) / 86_400_000;
  return (
    <span
      className={ageDays > 30 ? "text-chart-3" : undefined}
      title={`Last scanned ${new Date(lastScanAt).toLocaleString()}`}
    >
      scanned {timeAgo(lastScanAt)}
    </span>
  );
}

// The findings count is the single most useful number on this page, so it
// gets typographic weight and a fixed-width column rather than being one more
// item in a right-aligned run of text. Everything in the column lines up
// across rows, which is what makes 35 of them scannable instead of readable.
function FindingsColumn({ entry, scanned }: { entry?: TargetSummaryEntry; scanned: boolean }) {
  // Missing summary and never-scanned are different from clean, and neither
  // may render as a reassuring zero -- a repo nobody looked at is unknown,
  // not safe (#174).
  if (!entry || (entry.open === 0 && !scanned)) {
    return (
      <div className="w-28 shrink-0 text-right">
        <div className="text-sm text-muted-foreground/60">--</div>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground/60">not scanned</div>
      </div>
    );
  }

  if (entry.open === 0) {
    return (
      <div className="w-28 shrink-0 text-right">
        <div className="text-sm font-medium text-chart-5">0</div>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">open findings</div>
      </div>
    );
  }

  return (
    <div className="w-28 shrink-0 text-right">
      <div className="flex items-baseline justify-end gap-1.5">
        <span className="text-lg font-semibold leading-none text-foreground">{entry.open}</span>
        {entry.critical > 0 && (
          <span className="text-xs font-medium text-destructive" title={`${entry.critical} critical`}>
            {entry.critical}C
          </span>
        )}
        {entry.high > 0 && (
          <span className="text-xs font-medium text-chart-3" title={`${entry.high} high`}>
            {entry.high}H
          </span>
        )}
      </div>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">open findings</div>
    </div>
  );
}

// Issue #68: multi-select wrapper around #66's per-target "Add Pipeline"
// mechanism (see targets/[id]/pipeline-integration.tsx). Checkbox selection
// + bulk action bar UX follows the established pattern in
// components/findings-list.tsx (findings' bulk-triage bar) rather than
// inventing a new one.
export function TargetsList({
  targets,
  scanSummary = {},
  targetSummary = {},
}: {
  targets: Target[];
  // Issue #174: real per-target scan history and open-finding counts. Both
  // optional and defaulted -- callers without them (and a failed fetch on
  // the page, which degrades to {}) just render the card without that line.
  scanSummary?: ScanSummary;
  targetSummary?: TargetSummary;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Captured once at mount, same reasoning as ScanFreshness below: staleness
  // is measured in days, so a render that reads the live clock is impure for
  // no visible benefit, and React's purity rule (react-hooks/purity) flags a
  // bare Date.now() call during render.
  const [now] = useState(() => Date.now());
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [batch, setBatch] = useState<PipelineIntegrationBatch | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);

  // Issue #212: a scan running anywhere -- triggered from Scans, the target
  // page, or by another user -- shows up on this list, which previously had
  // no notion of in-flight work at all.
  const { activeScans } = useActiveScans();

  // Issue #125: search/criticality applied client-side over the already
  // -fetched target list, same as targets-filter-bar.tsx's URL-param
  // convention -- group_id stays a separate server-refetching filter
  // (components/group-filter.tsx).
  const search = (searchParams.get("search") ?? "").trim().toLowerCase();
  const criticality = searchParams.get("criticality") ?? "";
  const sort = (searchParams.get("sort") ?? "findings") as TargetSort;
  const page = Math.max(1, Number(searchParams.get("page") ?? "1") || 1);
  const pageSize = pageSizeFromParams(searchParams.get("page_size") ?? undefined);
  // Issue #224: quick-glance status tabs -- Wiz/Snyk-style presets over
  // "which of my repos need looking at" rather than making the reader
  // reconstruct that from the criticality/sort dropdowns every visit.
  // Client-side like search/criticality above (targetSummary/scanSummary are
  // already fully fetched), and stored in the URL like every other filter
  // here so it survives a reload/share.
  const quick = (searchParams.get("quick") ?? "all") as QuickFilter;

  function setQuick(next: QuickFilter) {
    const params = new URLSearchParams(searchParams.toString());
    if (next === "all") params.delete("quick");
    else params.set("quick", next);
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  // Counted against the full (search/criticality-filtered but not
  // quick-filtered) set so a tab's own count doesn't change when it's the
  // active one -- "Needs attention (6)" should mean the same 6 regardless of
  // which tab is currently selected.
  const quickCounts = useMemo(() => {
    const base = targets.filter((t) => {
      if (search) {
        const haystack = `${t.name} ${t.repo_url}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      if (criticality && t.label !== criticality) return false;
      return true;
    });
    let attention = 0;
    let unscanned = 0;
    let stale = 0;
    for (const t of base) {
      const entry = targetSummary[String(t.id)];
      if (entry && (entry.critical > 0 || entry.high > 0)) attention++;
      const at = scanSummary[String(t.id)]?.last_scan_at;
      if (!at) unscanned++;
      else if ((now - new Date(at).getTime()) / 86_400_000 > 30) stale++;
    }
    return { all: base.length, attention, unscanned, stale };
  }, [targets, search, criticality, targetSummary, scanSummary, now]);

  const filtered = useMemo(() => {
    const matched = targets.filter((t) => {
      if (search) {
        const haystack = `${t.name} ${t.repo_url}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      if (criticality && t.label !== criticality) return false;
      if (quick === "attention") {
        const entry = targetSummary[String(t.id)];
        if (!entry || (entry.critical === 0 && entry.high === 0)) return false;
      }
      if (quick === "unscanned" && scanSummary[String(t.id)]?.last_scan_at) return false;
      if (quick === "stale") {
        const at = scanSummary[String(t.id)]?.last_scan_at;
        if (!at || (now - new Date(at).getTime()) / 86_400_000 <= 30) return false;
      }
      return true;
    });

    // Default sort is "most findings", because that is the question this
    // page exists to answer. Alphabetical buried the one repo with 1137 open
    // findings in the middle of 35 rows.
    const openOf = (t: Target) => targetSummary[String(t.id)]?.open ?? 0;
    const criticalOf = (t: Target) => targetSummary[String(t.id)]?.critical ?? 0;
    const highOf = (t: Target) => targetSummary[String(t.id)]?.high ?? 0;
    const scannedAt = (t: Target) => {
      const at = scanSummary[String(t.id)]?.last_scan_at;
      return at ? new Date(at).getTime() : 0;
    };

    const byName = (a: Target, b: Target) => a.name.localeCompare(b.name);

    return [...matched].sort((a, b) => {
      switch (sort) {
        case "name":
          return byName(a, b);
        case "stale":
          // Never-scanned first: an unscanned repo is the least-known, not
          // the most recently checked. scannedAt() returns 0 for them, which
          // sorts them to the front under ascending order.
          return scannedAt(a) - scannedAt(b) || byName(a, b);
        case "severity":
          return (
            criticalOf(b) - criticalOf(a) || highOf(b) - highOf(a) || openOf(b) - openOf(a) || byName(a, b)
          );
        case "findings":
        default:
          return openOf(b) - openOf(a) || criticalOf(b) - criticalOf(a) || byName(a, b);
      }
    });
  }, [targets, search, criticality, quick, sort, targetSummary, scanSummary, now]);

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
    // Acts on the visible page, matching Findings' "Select all on this page".
    setSelected(checked ? new Set(visible.map((t) => t.id)) : new Set());
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

  // ---------------------------------------------------------------------
  // Issue #35: Mass CI/CD Rollout Engine -- scope-based sibling to the
  // manual multi-select bulk flow above. Instead of checking boxes, the
  // caller picks a whole workspace / repo Group / "every repo I can see"
  // and optionally a Custom Workflow Builder template (workflow-templates
  // tab in Admin); the backend resolves the scope into a target set and
  // reuses the exact same PipelineIntegrationBatch tracking + polling as
  // the bulk flow (batch state above is shared for both).
  // ---------------------------------------------------------------------
  const [massOpen, setMassOpen] = useState(false);
  const [massScope, setMassScope] = useState<"all" | "workspace" | "group">("workspace");
  const [chosenMassWorkspaceId, setMassWorkspaceId] = useState<number | "">("");
  const [chosenMassGroupId, setMassGroupId] = useState<number | "">("");
  const [chosenMassTemplateId, setMassTemplateId] = useState<number | "">("");
  const [massSubmitting, setMassSubmitting] = useState(false);
  const [massError, setMassError] = useState<string | null>(null);

  // Fetched only once the dialog opens, and everything below it derives from
  // the selection rather than being cleared by a cascade of effects. The
  // effect version reset four state slots on every scope/workspace change,
  // which is where the group and template pickers could end up holding an id
  // that no longer belonged to the selected workspace.
  const { data: massWorkspaces, error: massWorkspacesError } = useAsyncData<WorkspaceSummary[]>(
    () => api.workspaces(),
    { enabled: massOpen },
  );
  const massWorkspaceId = chosenMassWorkspaceId !== "" ? chosenMassWorkspaceId : (massWorkspaces?.[0]?.id ?? "");
  const workspaces = massWorkspaces;

  const scopeNeedsWorkspace = massScope !== "all" && massWorkspaceId !== "";
  const { data: scopedLists } = useAsyncData<[Group[], PipelineWorkflowTemplate[]]>(
    () =>
      Promise.all([
        api.groups(massWorkspaceId as number),
        api.pipelineTemplates(massWorkspaceId as number),
      ]),
    { enabled: scopeNeedsWorkspace, deps: [massScope, massWorkspaceId] },
  );
  const [groupsInWorkspace, templatesInWorkspace] = scopeNeedsWorkspace
    ? (scopedLists ?? [null, null])
    : [null, null];

  // A group/template id is only meaningful inside the workspace it came
  // from, so it is validated against the current lists instead of being
  // cleared by an effect that could run a render too late.
  const massGroupId =
    chosenMassGroupId !== "" && groupsInWorkspace?.some((g) => g.id === chosenMassGroupId)
      ? chosenMassGroupId
      : "";
  const massTemplateId =
    chosenMassTemplateId !== "" && templatesInWorkspace?.some((t) => t.id === chosenMassTemplateId)
      ? chosenMassTemplateId
      : "";

  async function startMassRollout() {
    setMassError(null);
    if (massScope === "workspace" && massWorkspaceId === "") {
      setMassError("choose a workspace");
      return;
    }
    if (massScope === "group" && massGroupId === "") {
      setMassError("choose a group");
      return;
    }
    setMassSubmitting(true);
    try {
      const res = await api.massPipelineRollout({
        scope: massScope,
        workspace_id: massScope === "workspace" || massScope === "group" ? (massWorkspaceId as number) : undefined,
        group_id: massScope === "group" ? (massGroupId as number) : undefined,
        workflow_template_id: massTemplateId === "" ? undefined : (massTemplateId as number),
      });
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
        scope_label: res.scope_label,
      });
      setMassOpen(false);
    } catch (e) {
      setMassError(e instanceof Error ? e.message : "failed to start mass rollout");
    } finally {
      setMassSubmitting(false);
    }
  }

  // The list rendered every target with no pagination: 35 rows is ~3000px of
  // scroll today, and this page is the inventory for an org that may onboard
  // hundreds. Paged client-side rather than server-side because search,
  // criticality and sort already filter the already-fetched list here --
  // adding a server round-trip just for slicing would make those three
  // interactions slower for no gain.
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const clampedPage = Math.min(page, totalPages);
  const visible = filtered.slice((clampedPage - 1) * pageSize, clampedPage * pageSize);

  const allSelected = visible.length > 0 && visible.every((t) => selected.has(t.id));

  return (
    <div className="flex flex-col gap-2">
      {/* Issue #224: quick-glance status tabs above the list, same idea as
          Snyk's target-list status filters -- "which of my repos need
          looking at" answered in one click instead of reconstructing it
          from the criticality/sort dropdowns. */}
      <div className="flex flex-wrap gap-1 border-b border-border pb-2">
        {QUICK_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setQuick(f.value)}
            className={cn(
              "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
              quick === f.value
                ? "bg-accent text-accent-strong"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            {f.label}
            <span className="ml-1.5 text-muted-foreground">({quickCounts[f.value]})</span>
          </button>
        ))}
      </div>

      <div className="flex items-center justify-between gap-2">
        {filtered.length > 0 ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              aria-label="Select all targets"
              className="h-4 w-4 accent-primary"
              checked={allSelected}
              onChange={(e) => toggleAll(e.target.checked)}
            />
            <span>
              Select all on this page{" "}
              {(search || criticality) && `(${filtered.length} of ${targets.length} match)`}
            </span>
          </div>
        ) : (
          <span />
        )}
        {/* Issue #35: fleet-wide alternative to the checkbox-driven bulk bar
            below -- rolls out to an entire workspace/group/every accessible
            repo without paging through a manual selection. */}
        {/* The name implies something irreversible across many repositories,
            and an external review found nothing on hover or nearby saying
            what it rolls out. It opens a scope picker -- it does not fire on
            click -- and what it ultimately does is open a PR per repo, which
            someone still has to merge. Both worth stating. */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => setMassOpen((v) => !v)}
          title="Open a PR adding the Rikugan scan workflow to every repo in a workspace or group. Opens a scope picker first; nothing is changed until you confirm, and each PR still needs merging."
          className="h-7 text-xs"
        >
          <Rocket className="mr-1 h-3.5 w-3.5" />
          Mass Rollout
        </Button>
      </div>

      {massOpen && (
        <div className="flex flex-col gap-3 rounded-md border border-border bg-card p-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-foreground">Mass CI/CD Rollout</span>
            <button onClick={() => setMassOpen(false)} aria-label="Close mass rollout" className="text-muted-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            Add the Rikugan pipeline scan workflow to every repo in a scope at once, instead of selecting them one
            by one.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
              value={massScope}
              onChange={(e) => setMassScope(e.target.value as typeof massScope)}
              aria-label="Rollout scope"
            >
              <option value="workspace">Entire workspace</option>
              <option value="group">A repo group</option>
              <option value="all">All repos I can access</option>
            </select>

            {(massScope === "workspace" || massScope === "group") && (
              <select
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={massWorkspaceId}
                onChange={(e) => setMassWorkspaceId(e.target.value === "" ? "" : Number(e.target.value))}
                aria-label="Workspace"
              >
                <option value="">Choose workspace...</option>
                {workspaces?.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                  </option>
                ))}
              </select>
            )}

            {massScope === "group" && (
              <select
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={massGroupId}
                onChange={(e) => setMassGroupId(e.target.value === "" ? "" : Number(e.target.value))}
                aria-label="Repo group"
              >
                <option value="">Choose group...</option>
                {groupsInWorkspace?.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            )}

            {(massScope === "workspace" || massScope === "group") && templatesInWorkspace && templatesInWorkspace.length > 0 && (
              <select
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={massTemplateId}
                onChange={(e) => setMassTemplateId(e.target.value === "" ? "" : Number(e.target.value))}
                aria-label="Custom workflow template"
              >
                <option value="">Default scanner set</option>
                {templatesInWorkspace.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            )}

            <Button size="sm" disabled={massSubmitting} onClick={startMassRollout} className="h-9 text-xs">
              {massSubmitting ? "Starting..." : "Start Rollout"}
            </Button>
          </div>
          {(massError ?? massWorkspacesError?.message) && (
            <p className="text-xs text-destructive">{massError ?? massWorkspacesError?.message}</p>
          )}
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
              {/* Issue #35: only set for a scope-based Mass Rollout batch --
                  "" for #68's original manual checkbox-selection batches. */}
              {batch.scope_label && (
                <span className="ml-2 text-xs font-normal text-muted-foreground">({batch.scope_label})</span>
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
                      <a href={safeHref(item.pr_url)} target="_blank" rel="noreferrer" className="text-accent-strong underline underline-offset-2">
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

      {filtered.length === 0 && targets.length > 0 && (
        <EmptyState
          icon={Rocket}
          title="No targets match these filters"
          description="Try clearing search or the criticality filter."
        />
      )}

      {/* Unconditional: ActivityPagination self-gates. Gating here on
          filtered.length > pageSize hid the rows-per-page selector as soon as
          the user picked a size larger than the result set, stranding them. */}
      <ActivityPagination total={filtered.length} page={clampedPage} pageSize={pageSize} position="top" />

      {/* Issue #224: one bordered container with thin dividers between rows,
          replacing a bordered `Card` per row -- 35+ nested boxes each with
          their own border/radius/shadow was the single biggest visual-noise
          contributor on this page next to Findings; a single outer border
          plus a hairline between rows (Snyk/Wiz's own target-list pattern)
          reads as one inventory instead of a stack of separate cards, with
          zero loss of information -- every column, badge and link below is
          unchanged. */}
      {visible.length > 0 && (
      <div className="divide-y divide-border rounded-lg border border-border bg-card">
      {visible.map((t) => (
          <div key={t.id} className="flex items-center gap-3 px-4 transition-colors hover:bg-secondary/40"
            style={{ paddingTop: "var(--density-row-py)", paddingBottom: "var(--density-row-py)" }}
          >
            <input
              type="checkbox"
              aria-label={`Select ${t.name}`}
              className="h-4 w-4 shrink-0 accent-primary"
              checked={selected.has(t.id)}
              onChange={(e) => toggleOne(t.id, e.target.checked)}
              onClick={(e) => e.stopPropagation()}
            />
            <Link href={`/targets/${t.id}`} className="flex min-w-0 flex-1 items-center gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium text-foreground">{t.name}</span>
                  <CriticalityChip label={t.label} />
                  <AiRepoBadge target={t} />
                  {t.pipeline_integrated && (
                    <Badge
                      variant="outline"
                      title="CI pipeline scanning integrated"
                      className="shrink-0 border-chart-5/40 px-1.5 py-0 text-[10px] text-chart-5"
                    >
                      CI
                    </Badge>
                  )}
                  {t.groups.map((g) => (
                    <GroupBadge key={g.id} group={g} />
                  ))}
                </div>
                {/* One metadata line instead of two. The clone URL was the
                    widest thing on the card and the least useful -- the repo
                    name above already identifies it, and the card links
                    through. Owner/name is kept so forks stay distinguishable;
                    the full URL is on hover and on the detail page. */}
                <div className="mt-0.5 flex items-center gap-2 truncate text-[11px] text-muted-foreground">
                  <span className="font-mono" title={t.repo_url}>
                    {repoSlug(t.repo_url)}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{t.default_branch}</span>
                  <span aria-hidden="true">·</span>
                  {/* A scan in flight replaces the freshness line entirely.
                      Showing "last scanned 3 days ago" while a scan is
                      running is the exact complaint behind #212: the row
                      stated the most stale thing it knew and said nothing
                      about the work happening right then. */}
                  {activeScans[String(t.id)]?.length ? (
                    <ScanProgress
                      phase="running"
                      tool={activeScans[String(t.id)]!.map((scan) => scan.tool).join(", ")}
                      elapsedSeconds={Math.max(
                        ...activeScans[String(t.id)]!.map((scan) => scan.elapsed_seconds),
                      )}
                      // Only when every running tool has an estimate: the
                      // repo is done when its slowest scan is, and a
                      // countdown that ignores an unestimated tool would
                      // hit zero while work continued.
                      etaSeconds={
                        activeScans[String(t.id)]!.every((scan) => scan.eta_seconds !== null)
                          ? Math.max(...activeScans[String(t.id)]!.map((scan) => scan.eta_seconds!))
                          : null
                      }
                    />
                  ) : (
                    <ScanFreshness lastScanAt={scanSummary[String(t.id)]?.last_scan_at ?? null} />
                  )}
                </div>
              </div>
              <FindingsColumn
                entry={targetSummary[String(t.id)]}
                scanned={Boolean(scanSummary[String(t.id)]?.last_scan_at)}
              />
              {/* Labelled like the findings column beside it. A bare "2/5"
                  floating at the row end is unreadable as anything -- the
                  same complaint #174 fixed for the old bare "weight 2". */}
              <div className="w-12 shrink-0 text-right" title={CRITICALITY_WEIGHT_EXPLANATION}>
                <div className="text-sm text-muted-foreground">{t.criticality_weight}/5</div>
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground">risk</div>
              </div>
            </Link>
          </div>
      ))}
      </div>
      )}

      {filtered.length > pageSize && (
        <ActivityPagination total={filtered.length} page={clampedPage} pageSize={pageSize} />
      )}
    </div>
  );
}
