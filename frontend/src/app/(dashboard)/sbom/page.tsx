"use client";

import { ChangeEvent, useEffect, useRef, useState } from "react";
import {
  api,
  type Target,
  type SbomExportFormat,
  type FindingGroupListResult,
  type OrgSbomComponent,
  type OrgSbomResult,
  type SbomComponent,
} from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspaceScopedSelection } from "@/hooks/use-workspace-scoped-selection";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TargetPicker, ALL_TARGETS } from "@/components/features/targets";
import { useSearchParams } from "next/navigation";
import { AiBomPanel } from "@/components/features/intelligence";
import { ListRow } from "@/components/ui/list-row";
import { PaginatedList } from "@/components/ui/paginated-list";
import { pageSizeFromParams } from "@/lib/pagination";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { FindingsGroupsList } from "@/components/features/findings";
import { PageHeader } from "@/components/ui/page-header";
import { HelpHint } from "@/components/ui/help-hint";
import { HELP_CONTENT } from "@/lib/help-content";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import {
  DocGenStep,
  DocGenToggle,
  DocGenOption,
  DocumentGeneratorPanel,
  WhatsIncludedCard,
} from "@/components/features/intelligence";
import { cn } from "@/lib/utils";
import { Package, PackageSearch } from "lucide-react";
import { formatSince } from "@/lib/format/date";

const SBOM_FORMATS: DocGenOption[] = [
  { value: "cyclonedx-json", label: "CycloneDX JSON" },
  { value: "spdx-json", label: "SPDX JSON" },
  { value: "csv", label: "CSV" },
  { value: "pdf", label: "PDF" },
];

const SBOM_FORMAT_EXT: Record<SbomExportFormat, string> = {
  "cyclonedx-json": "json",
  "spdx-json": "spdx.json",
  csv: "csv",
  pdf: "pdf",
};

const NEW_BADGE_COLOR = "border-chart-5/20 bg-chart-5/10 text-chart-5";

type Tab = "components" | "vulnerabilities" | "aibom";

/**
 * One component of the per-target inventory.
 *
 * Every field the previous card showed is still here; what changed is which
 * of them gets the width. The purl is the longest string in the row and the
 * least discriminating -- it restates name, version and ecosystem in a
 * machine-readable form -- so it is capped and truncated with the full value
 * on hover, and the name/version pair takes the space it was using.
 */
function SbomComponentRow({ component, showNew }: { component: SbomComponent; showNew: boolean }) {
  return (
    <ListRow>
      <div className="flex min-w-0 flex-1 items-baseline gap-2">
        <span className="truncate font-mono text-sm text-foreground" title={component.name}>
          {component.name}
        </span>
        <span className="shrink-0 font-mono text-xs text-foreground">{component.version}</span>
        {showNew && component.is_new && (
          <Badge
            variant="outline"
            className={`shrink-0 px-1.5 py-0 text-[10px] font-bold uppercase tracking-wide ${NEW_BADGE_COLOR}`}
          >
            New
          </Badge>
        )}
      </div>
      {/* Fixed-width trailing columns, the same shape the grouped findings
          list uses: a ragged right edge is what makes a long list unreadable,
          because nothing lines up to compare down the page. */}
      <span className="w-20 shrink-0 truncate text-xs text-muted-foreground">{component.package_type}</span>
      {/* Provenance. The column keeps its width even with nothing in it: a
          row written before sources were recorded has no answer, and a blank
          slot says that more honestly than a guessed default would. */}
      <span className="w-24 shrink-0 truncate text-xs text-muted-foreground">{component.source ?? ""}</span>
      <span
        className="w-64 shrink truncate font-mono text-[11px] text-muted-foreground"
        title={component.purl}
      >
        {component.purl}
      </span>
      <span className="w-24 shrink-0 truncate text-right text-xs text-muted-foreground">
        {formatSince(component.first_seen)}
      </span>
    </ListRow>
  );
}

function OrgSbomRow({ component }: { component: OrgSbomComponent }) {
  const [expanded, setExpanded] = useState(false);
  const repoCount = component.targets.length;

  return (
    <ListRow>
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-baseline gap-2">
            <span className="truncate font-mono text-sm text-foreground" title={component.name}>
              {component.name}
            </span>
            <span className="shrink-0 font-mono text-xs text-foreground">{component.version}</span>
            <span className="shrink-0 text-xs text-muted-foreground">{component.package_type}</span>
          </div>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="shrink-0 text-xs font-medium text-muted-foreground hover:text-foreground"
          >
            {repoCount} repo{repoCount === 1 ? "" : "s"} {expanded ? "▴" : "▾"}
          </button>
        </div>
        {expanded && (
          <div className="flex flex-wrap gap-1.5 border-t border-border pt-2">
            {component.targets.map((t) => (
              <Badge key={t.id} variant="outline" className="text-xs">
                {t.name}
              </Badge>
            ))}
          </div>
        )}
      </div>
    </ListRow>
  );
}

export default function SbomPage() {
  const { activeWorkspaceId } = useWorkspaceContext();
  // (#506/#519) A specific chosen target belongs to whichever workspace was
  // active when it was picked; resets on a workspace switch, "All
  // repositories" (ALL_TARGETS) exempted -- see the hook's own doc comment.
  const [chosenTargetIds, setChosenTargetIds] = useWorkspaceScopedSelection(activeWorkspaceId, ALL_TARGETS);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets({ workspace_id: activeWorkspaceId }), {
    deps: [activeWorkspaceId],
  });
  // Filtered, not just fetched-with-workspace_id: useAsyncData keeps the
  // previous workspace's targets on screen while the new request is still in
  // flight, and this filter is what stops targetId below from falling back
  // to one of those stale rows during that window.
  const targets = (targetsData ?? []).filter(
    (t) => activeWorkspaceId === null || t.workspace_id === activeWorkspaceId,
  );
  // Derived rather than seeded in an effect, same reasoning as
  // WorkspaceContext's activeWorkspaceId: the user's choice wins and a
  // reload cannot move them. `??`, not a length check: `chosenTargetIds` is
  // `null` only when nothing has been explicitly chosen yet -- an explicit
  // Clear in the picker sets it to `[]`, which must stay `[]` here rather
  // than silently snapping back to the default (#519 review).
  const targetIds = chosenTargetIds ?? (targets[0] ? [targets[0].id] : []);
  const isOrgWide = targetIds.includes(ALL_TARGETS);
  // Generate/export/import/upload all write one repo's persisted inventory
  // (POST /api/sbom/{id}/...), so they -- and the tabbed single-repo view
  // below -- stay scoped to exactly one repo. `targetId` is that repo, or
  // null while org-wide or several-selected has taken over.
  const targetId = !isOrgWide && targetIds.length === 1 ? targetIds[0] : null;
  const multiSelected = !isOrgWide && targetIds.length > 1;
  const setTargetId = setChosenTargetIds;
  // Only meaningful relative to a scan just triggered in this session; the
  // plain GET on load always reports is_new: false, so we don't show the
  // "New" badge at all until a POST has completed here (same convention as
  // the API Discovery page).
  // Tagged with the target it describes rather than cleared by an effect on
  // target change: a "3 new components" badge belonging to a different repo
  // is worse than no badge, and deriving the match makes that impossible.
  const [lastScan, setLastScan] = useState<{
    targetId: number;
    new_count: number;
    malware?: { status: "clean" | "found" | "failed"; malicious_count: number; findings_created: number };
  } | null>(null);
  const [tab, setTab] = useState<Tab>("components");
  const searchParams = useSearchParams();
  const [exporting, setExporting] = useState(false);
  const [format, setFormat] = useState<SbomExportFormat>("cyclonedx-json");


  const [orgExportError, setOrgExportError] = useState<string | null>(null);
  const [orgExporting, setOrgExporting] = useState(false);
  const [orgSearch, setOrgSearch] = useState("");
  const [importingGithub, setImportingGithub] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const cancelPollRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    return () => {
      cancelPollRef.current?.();
    };
  }, []);

  const {
    data: orgSbom,
    error: orgLoadError,
    isInitialLoading: orgInitialLoading,
    isRefreshing: orgRefreshing,
  } = useAsyncData<OrgSbomResult>(() => api.getOrgSbom(activeWorkspaceId), {
    enabled: isOrgWide,
    deps: [isOrgWide, activeWorkspaceId],
  });

  // Several specific repos selected at once (not "All", not one repo): N
  // parallel per-repo SBOM fetches, merged and tagged with which repo each
  // component came from -- each GET already returns that repo's full
  // unpaginated component list, so this is a plain client-side concat rather
  // than a new backend aggregate endpoint duplicating getOrgSbom's.
  const {
    data: multiSbom,
    error: multiSbomError,
    isInitialLoading: multiSbomLoading,
  } = useAsyncData(
    () =>
      Promise.allSettled(
        targetIds.map((id) =>
          api.getSbom(id).then((res) => ({
            targetId: id,
            targetName: targets.find((t) => t.id === id)?.name ?? `target #${id}`,
            components: res.components ?? [],
          })),
        ),
      ).then((settled) => ({
        // One repo's SBOM fetch failing must not blank out every other
        // selected repo's components -- Promise.all would reject the whole
        // batch on a single rejection.
        fulfilled: settled.flatMap((r) => (r.status === "fulfilled" ? [r.value] : [])),
        failedTargetIds: targetIds.filter((_, i) => settled[i].status === "rejected"),
      })),
    { enabled: multiSelected, deps: [targetIds.join(","), multiSelected] },
  );
  const mergedComponents = (multiSbom?.fulfilled ?? []).flatMap((r) =>
    r.components.map((c) => ({ ...c, repoTargetId: r.targetId, repoName: r.targetName })),
  );
  const multiSbomFailedTargetNames = (multiSbom?.failedTargetIds ?? []).map(
    (id) => targets.find((t) => t.id === id)?.name ?? `target #${id}`,
  );
  // A workspace switch re-triggers this fetch (activeWorkspaceId is a dep)
  // but useAsyncData keeps the previous workspace's org SBOM visible while it
  // is in flight; treated as loading too so that stale cross-workspace data
  // is never on screen, not just on first mount.
  const orgLoading = orgInitialLoading || orgRefreshing;

  async function exportOrgJson() {
    setOrgExporting(true);
    setOrgExportError(null);
    try {
      const blob = await api.exportOrgSbom(activeWorkspaceId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "sbom-org-wide.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setOrgExportError(e instanceof Error ? e.message : "organization SBOM export failed");
    } finally {
      setOrgExporting(false);
    }
  }

  const filteredOrgComponents = (orgSbom?.components ?? []).filter((c) =>
    c.name.toLowerCase().includes(orgSearch.trim().toLowerCase()),
  );

  const {
    data: persisted,
    error: persistedError,
    isInitialLoading: loading,
    refetch: reloadPersisted,
  } = useAsyncData(() => api.getSbom(targetId!), {
    enabled: targetId !== null,
    deps: [targetId],
  });
  const components = persisted?.components ?? null;
  const scanSummary = lastScan && lastScan.targetId === targetId ? lastScan : null;

  // Export failures and load failures are different events with the same
  // destination on screen; both must be able to surface.
  const orgDisplayError = orgExportError ?? orgLoadError?.message ?? null;

  const sbomPageSize = pageSizeFromParams(searchParams.get("page_size") ?? undefined);
  const sbomPageRaw = Math.max(1, Number(searchParams.get("page") ?? "1") || 1);
  const sbomTotalPages = Math.max(1, Math.ceil((components?.length ?? 0) / sbomPageSize));
  const sbomPage = Math.min(sbomPageRaw, sbomTotalPages);
  const visibleComponents = (components ?? []).slice((sbomPage - 1) * sbomPageSize, sbomPage * sbomPageSize);

  // The merged multi-repo view pages off the same URL params as the
  // single-target Components tab above (mutually exclusive views, never
  // both on screen). `getSbom` returns a repo's full unpaginated component
  // list -- on a target with thousands of components, rendering
  // `mergedComponents` in one unpaged PaginatedList call would put the
  // entire merged set in the DOM at once.
  const mergedTotalPages = Math.max(1, Math.ceil(mergedComponents.length / sbomPageSize));
  const mergedPage = Math.min(sbomPageRaw, mergedTotalPages);
  const visibleMergedComponents = mergedComponents.slice(
    (mergedPage - 1) * sbomPageSize,
    mergedPage * sbomPageSize,
  );

  // The org-wide list pages off the same URL params. Only one of the two
  // views is ever on screen -- the tabs below exist only for a single target
  // -- and each clamps its page to the result set it is actually paging, so
  // narrowing the search from page 6 lands on the last page that exists
  // rather than on an empty one that reads as "no components".
  const orgTotalPages = Math.max(1, Math.ceil(filteredOrgComponents.length / sbomPageSize));
  const orgPage = Math.min(sbomPageRaw, orgTotalPages);
  const visibleOrgComponents = filteredOrgComponents.slice(
    (orgPage - 1) * sbomPageSize,
    orgPage * sbomPageSize,
  );

  // OSS/dependency vulnerabilities aren't a new concept -- they are ordinary
  // findings -- so this filters the existing findings API rather than standing
  // up a parallel endpoint.
  //
  // Scoped by `category: "SCA"` rather than the old `tool: "trivy"` plus a
  // client-side `!!f.cve_id` filter. Category is derived from the tool by
  // app.core.tool_registry, so a second SCA scanner appears here the day it is
  // integrated instead of silently going missing, and trivy's own non-SCA
  // output (trivy-config is IaC, trivy-license is License) stops being pulled
  // in and then filtered back out by hand.
  //
  // Grouped, and really paginated. This previously requested page_size: 500
  // and handed the lot to FindingsList with `pageSize={Math.max(ossTotal, 1)}`,
  // so the pager rendered a single page covering everything while shipping up
  // to 500 rows in one response -- the same defect that was fixed on the
  // target detail page.
  const ossPageSize = pageSizeFromParams(searchParams.get("page_size") ?? undefined);
  const ossPageRaw = Math.max(1, Number(searchParams.get("page") ?? "1") || 1);
  const { data: ossGroups, isInitialLoading: ossLoading } = useAsyncData<FindingGroupListResult>(
    () =>
      api.findingGroups({
        target_id: targetId!,
        category: "SCA",
        page: ossPageRaw,
        page_size: ossPageSize,
      }),
    {
      enabled: targetId !== null,
      deps: [targetId, ossPageRaw, ossPageSize],
    },
  );
  // The Components table above and this tab both read the shared `page` param
  // (ActivityPagination writes it), and only one tab renders at a time. Paging
  // through Components and then switching here would otherwise ask for a page
  // this result set does not have and render an empty list that looks like
  // "no vulnerabilities". Clamped so an out-of-range page shows the first one.
  const ossTotalGroups = ossGroups?.total ?? 0;
  const ossTotalPages = Math.max(1, Math.ceil(ossTotalGroups / ossPageSize));
  const ossPage = Math.min(ossPageRaw, ossTotalPages);
  const ossTotal = ossGroups?.total_findings ?? 0;

  async function run() {
    if (targetId === null) return;
    const runTargetId = targetId;
    setRunning(true);
    setError(null);
    cancelPollRef.current?.();
    try {
      // POST /api/sbom/{target_id} now dispatches a Celery task and returns
      // immediately with status: "running" (#59) instead of blocking until
      // the clone+dependency-graph import finishes; poll
      // GET /api/sbom/{target_id}/runs/{run_id} until it's done.
      const dispatch = await api.generateSbom(runTargetId);
      cancelPollRef.current = pollUntilSettled(
        () => api.getSbomRun(runTargetId, dispatch.run_id),
        (run) => {
          if (run.status === "completed") {
            // Refetch rather than writing `run.components` straight in: the
            // persisted SBOM is the single owner of this list, and a second
            // writer is what made the previous version's loading states
            // disagree with what was on screen.
            reloadPersisted();
            setLastScan({ targetId: runTargetId, new_count: run.new_count });
            setRunning(false);
          } else if (run.status === "failed") {
            setError(run.error || "SBOM generation failed");
            setRunning(false);
          }
        },
        {
          onError: (e) => {
            setError(e instanceof Error ? e.message : "SBOM generation failed");
            setRunning(false);
          },
        },
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "SBOM generation failed");
      setRunning(false);
    }
  }

  async function exportJson() {
    if (targetId === null) return;
    setExporting(true);
    setError(null);
    try {
      const blob = await api.exportSbom(targetId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sbom-${currentTarget?.name ?? targetId}.${SBOM_FORMAT_EXT[format]}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "SBOM export failed");
    } finally {
      setExporting(false);
    }
  }

  async function importFromGithub() {
    if (targetId === null) return;
    setImportingGithub(true);
    setError(null);
    try {
      const res = await api.importGithubSbom(targetId);
      reloadPersisted();
      setLastScan({ targetId, new_count: res.new_count, malware: res.malware });
    } catch (e) {
      setError(e instanceof Error ? e.message : "GitHub SBOM import failed");
    } finally {
      setImportingGithub(false);
    }
  }

  async function onUploadFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file || targetId === null) return;
    setUploading(true);
    setError(null);
    try {
      const res = await api.uploadSbom(targetId, file);
      reloadPersisted();
      setLastScan({ targetId, new_count: res.new_count, malware: res.malware });
    } catch (err) {
      setError(err instanceof Error ? err.message : "SBOM upload failed");
    } finally {
      setUploading(false);
    }
  }

  const showBusy = loading || running;
  const currentTarget = targets.find((t) => t.id === targetId);
  // (#273) Generate, Import from GitHub and Upload all write this target's
  // dependency inventory and run the OSV malware check over it, so all
  // three are refused server-side for a deactivated target. Export is
  // deliberately NOT gated: reading back an inventory captured before
  // deactivation is a large part of why someone deactivates rather than
  // deletes.
  const targetDeactivated = currentTarget?.is_active === false;
  const deactivatedHint = targetDeactivated
    ? "This target is deactivated; scanning is off. Reactivate it on the target page."
    : undefined;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="SBOM & OSS Vulnerabilities"
        description="Every dependency recorded for this target, from GitHub's dependency graph and any SBOM documents you have uploaded."
        badge={<HelpHint topic={HELP_CONTENT.sbom} />}
      />

      <DocumentGeneratorPanel
        layout="stacked"
        steps={[
          <DocGenStep key="target" n={1} label="Target">
            <TargetPicker targets={targets} value={targetIds} onChange={setTargetId} allowAll />
          </DocGenStep>,
          ...(targetId !== null
            ? [
                <DocGenStep key="scope" n={2} label="Scope">
                  <div className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground">
                    Default branch{currentTarget ? ` (${currentTarget.default_branch})` : ""}
                  </div>
                </DocGenStep>,
                <DocGenStep key="format" n={3} label="Format">
                  <DocGenToggle options={SBOM_FORMATS} value={format} onChange={(v) => setFormat(v as SbomExportFormat)} />
                </DocGenStep>,
                <WhatsIncludedCard
                  key="included"
                  items={[
                    "Every dependency on file for this target, with its version where the source recorded one",
                    "Where each component was recorded from, so an entry can be traced back to its source",
                    "Each component's package URL (purl) and ecosystem",
                  ]}
                />,
              ]
            : []),
        ]}
        generateLabel={targetId !== null ? "Generate SBOM" : undefined}
        onGenerate={targetId !== null ? run : undefined}
        generating={running}
        generateDisabled={targetId === null || targetDeactivated}
        extra={
          targetId !== null ? (
            <div className="flex flex-col gap-2">
              {targetDeactivated && (
                <p className="text-xs text-warning">
                  This target is deactivated; scanning is off, so generating or importing an inventory is
                  disabled. The SBOM already on file stays readable and exportable.
                </p>
              )}
              <Button
                variant="outline"
                className="w-full justify-center"
                onClick={exportJson}
                disabled={exporting || targetId === null || !components || components.length === 0}
              >
                {exporting ? "Exporting..." : `Export SBOM (${SBOM_FORMATS.find((f) => f.value === format)?.label})`}
              </Button>
              <Button
                variant="outline"
                className="w-full justify-center"
                onClick={importFromGithub}
                disabled={importingGithub || targetId === null || targetDeactivated}
                title={deactivatedHint}
              >
                {importingGithub ? "Importing..." : "Import from GitHub"}
              </Button>
              <Button
                variant="outline"
                className="w-full justify-center"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading || targetId === null || targetDeactivated}
                title={deactivatedHint}
              >
                {uploading ? "Uploading..." : "Upload SBOM"}
              </Button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,application/json"
                className="hidden"
                onChange={onUploadFile}
                aria-label="Upload SBOM document"
              />
            </div>
          ) : isOrgWide ? (
            <Button
              variant="outline"
              className="w-full justify-center"
              onClick={exportOrgJson}
              disabled={orgExporting || !orgSbom || orgSbom.components.length === 0}
            >
              {orgExporting ? "Exporting..." : "Export Org SBOM (JSON)"}
            </Button>
          ) : null
        }
      />

      {multiSelected && (
        <p className="text-sm text-muted-foreground">
          Generating, exporting, importing and uploading an SBOM all act on one repository at a time --
          select a single repository above to use them. Showing already-persisted components across the{" "}
          {targetIds.length} selected repositories below.
        </p>
      )}

      {multiSelected && (
        <div className="flex flex-col gap-4">
          {/* The whole batch only fails to load when the aggregate fetcher
              itself throws; an individual repo's SBOM fetch failing is
              reported per-repo below instead. */}
          {multiSbomError && <p className="text-sm text-destructive">{multiSbomError.message}</p>}
          {multiSbomLoading && <SkeletonList count={4} />}
          {!multiSbomLoading && !multiSbomError && (
            <PaginatedList
              items={visibleMergedComponents}
              total={mergedComponents.length}
              page={mergedPage}
              pageSize={sbomPageSize}
              summary={`${mergedComponents.length} component${mergedComponents.length === 1 ? "" : "s"} across ${targetIds.length} repositories${multiSbomFailedTargetNames.length > 0 ? ` (couldn't load ${multiSbomFailedTargetNames.join(", ")})` : ""}`}
              getKey={(c) => `${c.repoTargetId}-${c.id}`}
              renderItem={(c) => (
                <ListRow>
                  <div className="flex min-w-0 flex-1 items-baseline gap-2">
                    <span className="truncate font-mono text-sm text-foreground" title={c.name}>
                      {c.name}
                    </span>
                    <span className="shrink-0 font-mono text-xs text-foreground">{c.version}</span>
                  </div>
                  <Badge variant="outline" className="shrink-0 text-[10px]">
                    {c.repoName}
                  </Badge>
                  <span className="w-20 shrink-0 truncate text-xs text-muted-foreground">{c.package_type}</span>
                </ListRow>
              )}
              empty={
                <EmptyState
                  icon={Package}
                  title="No SBOM data yet"
                  description="Select a single repository above and generate an SBOM to see its dependency inventory here."
                  bare
                />
              }
            />
          )}
        </div>
      )}

      {isOrgWide && (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            Aggregated from every already-scanned target&apos;s persisted SBOM
            (default branch); read-only, no new scans are triggered here.
          </p>

          {orgDisplayError && <p className="text-sm text-destructive">{orgDisplayError}</p>}

          {orgLoading && <SkeletonList count={4} />}

          {!orgLoading && orgSbom && (
            <>
              <StatGrid columns={2}>
                <StatCard
                  label="Targets with SBOM"
                  value={`${orgSbom.targets_with_sbom_count} / ${orgSbom.total_targets_count}`}
                />
                <StatCard
                  label="Unique components"
                  value={orgSbom.unique_component_count}
                />
              </StatGrid>

              <Input
                placeholder="Search components by name..."
                value={orgSearch}
                onChange={(e) => setOrgSearch(e.target.value)}
                className="max-w-sm"
              />

              <PaginatedList
                items={visibleOrgComponents}
                total={filteredOrgComponents.length}
                page={orgPage}
                pageSize={sbomPageSize}
                summary={`${filteredOrgComponents.length} component${
                  filteredOrgComponents.length === 1 ? "" : "s"
                }${orgSearch ? ` matching "${orgSearch}"` : ""}`}
                getKey={(c) => `${c.name}@${c.version}@${c.purl}`}
                renderItem={(c) => <OrgSbomRow component={c} />}
                empty={
                  orgSbom.components.length === 0 ? (
                    <EmptyState
                      icon={Package}
                      title="No SBOM data yet"
                      description="Select a repository above and generate an SBOM to see its dependency inventory here."
                      bare
                    />
                  ) : (
                    <EmptyState icon={PackageSearch} title="No components match your search" bare />
                  )
                }
              />
            </>
          )}
        </div>
      )}

      {targetId !== null && (
        <>
          {/* Scan/export failures and the persisted-SBOM load failure share
              one slot; a load failure must not be swallowed just because no
              scan has run. */}
          {(error ?? persistedError?.message) && (
            <p className="text-sm text-destructive">{error ?? persistedError?.message}</p>
          )}

          {!error && !persistedError && scanSummary && (
            <p className="text-sm text-foreground">
              {scanSummary.new_count > 0
                ? `${scanSummary.new_count} new component${scanSummary.new_count === 1 ? "" : "s"} found`
                : "No new components"}
            </p>
          )}

          {/* Issue #226 review: this used to be gated on status === "found"
              alone, so a "failed" malware check rendered nothing at all;
              pixel-identical to a successful check that found nothing. The
              backend goes out of its way to distinguish "checked, clean"
              from "could not check" (osv_malware.py's None-vs-{} split);
              collapsing that back together in the one place a person
              actually reads it would undo the whole point. */}
          {!error && !persistedError && scanSummary?.malware?.status === "found" && (
            <p className="text-sm text-destructive">
              {scanSummary.malware.malicious_count} malicious package
              {scanSummary.malware.malicious_count === 1 ? "" : "s"} detected via OSV
            </p>
          )}
          {!error && !persistedError && scanSummary?.malware?.status === "failed" && (
            <p className="text-sm text-destructive">
              Malware check failed to run; these components have <strong>not</strong> been checked against OSV.
              This is not an all-clear.
            </p>
          )}

          <div className="flex gap-1 border-b border-border">
            <button
              onClick={() => setTab("components")}
              className={cn(
                "px-3 py-2 text-sm font-medium transition-colors",
                tab === "components"
                  ? "border-b-2 border-primary text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              Components{components ? ` (${components.length})` : ""}
            </button>
            <button
              onClick={() => setTab("vulnerabilities")}
              className={cn(
                "px-3 py-2 text-sm font-medium transition-colors",
                tab === "vulnerabilities"
                  ? "border-b-2 border-primary text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              OSS Vulnerabilities{ossGroups ? ` (${ossTotal})` : ""}
            </button>
            {/* Issue #190: models and datasets, the part a package SBOM is
                blind to. Populated by the same generation run. */}
            <button
              onClick={() => setTab("aibom")}
              className={cn(
                "px-3 py-2 text-sm font-medium transition-colors",
                tab === "aibom"
                  ? "border-b-2 border-primary text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              AI Bill of Materials
            </button>
          </div>

          {tab === "components" && (
            <>
              {showBusy && <SkeletonList count={3} />}
              {/* 1396 components on a real target, rendering them all was the
                  single longest scroll in the app; the shared list shell owns
                  the paging, the page-size control and the density-aware row
                  stack so this surface cannot drift from the others again. */}
              {!showBusy && components && (
                <PaginatedList
                  items={visibleComponents}
                  total={components.length}
                  page={sbomPage}
                  pageSize={sbomPageSize}
                  itemNoun="component"
                  getKey={(c) => c.id}
                  renderItem={(c) => <SbomComponentRow component={c} showNew={scanSummary !== null} />}
                  empty={
                    <EmptyState
                      icon={Package}
                      title="No components recorded yet"
                      description="Generate an SBOM to scan this target's dependency manifests."
                      bare
                    />
                  }
                />
              )}
            </>
          )}

          {tab === "aibom" && targetId !== null && (
            <AiBomPanel targetId={targetId} targetName={currentTarget?.name} />
          )}

          {tab === "vulnerabilities" && (
            <>
              {ossLoading && <SkeletonList count={3} />}
              {!ossLoading && ossGroups && (
                // The same grouped list the Findings page and the target's
                // Vulnerabilities tab use, so one CVE across several manifests
                // is one row, expanding to its occurrences and through to the
                // full detail drawer -- CVE/CWE/CVSS, fix versions, suggested
                // fix and per-finding triage. This tab was the last surface
                // still rendering the flat one-row-per-detection list.
                <FindingsGroupsList
                  groups={ossGroups.items}
                  total={ossGroups.total}
                  totalFindings={ossGroups.total_findings}
                  truncated={ossGroups.truncated}
                  page={ossPage}
                  pageSize={ossPageSize}
                  memberQuery={{ target_id: targetId!, category: "SCA" }}
                  targets={currentTarget ? [currentTarget] : targets}
                />
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
