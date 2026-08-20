"use client";

import { ChangeEvent, useEffect, useRef, useState } from "react";
import {
  api,
  Target,
  SbomExportFormat,
  Finding,
  OrgSbomComponent,
  OrgSbomResult,
} from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TargetPicker, ALL_TARGETS } from "@/components/target-picker";
import { useSearchParams } from "next/navigation";
import { AiBomPanel } from "@/components/aibom-panel";
import { ActivityPagination } from "@/components/activity-pagination";
import { pageSizeFromParams } from "@/lib/pagination";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { FindingsList } from "@/components/findings-list";
import {
  DocGenStep,
  DocGenToggle,
  DocGenOption,
  DocumentGeneratorPanel,
  WhatsIncludedCard,
} from "@/components/document-generator-panel";
import { cn } from "@/lib/utils";
import { Package, PackageSearch } from "lucide-react";

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

function formatSince(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `since ${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })}`;
}

type Tab = "components" | "vulnerabilities" | "aibom";

function OrgSbomRow({ component }: { component: OrgSbomComponent }) {
  const [expanded, setExpanded] = useState(false);
  const repoCount = component.targets.length;

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-2 px-4 py-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm text-foreground">
              {component.name}
            </span>
            <Badge variant="outline">{component.version}</Badge>
            <span className="text-xs text-muted-foreground">
              {component.package_type}
            </span>
          </div>
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-xs font-medium text-muted-foreground hover:text-foreground"
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
      </CardContent>
    </Card>
  );
}

export default function SbomPage() {
  const [chosenTargetId, setChosenTargetId] = useState<number | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets());
  const targets = targetsData ?? [];
  // Derived rather than seeded in an effect, same reasoning as
  // useWorkspacePicker: the user's choice wins and a reload cannot move them.
  const targetId = chosenTargetId ?? targets[0]?.id ?? null;
  const setTargetId = setChosenTargetId;
  // Only meaningful relative to a scan just triggered in this session -- the
  // plain GET on load always reports is_new: false, so we don't show the
  // "New" badge at all until a POST has completed here (same convention as
  // the API Discovery page).
  // Tagged with the target it describes rather than cleared by an effect on
  // target change: a "3 new components" badge belonging to a different repo
  // is worse than no badge, and deriving the match makes that impossible.
  const [lastScan, setLastScan] = useState<{ targetId: number; new_count: number } | null>(null);
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
    // Stop polling if the component unmounts (e.g. navigating away) mid-run.
    return () => cancelPollRef.current?.();
  }, []);

  const {
    data: orgSbom,
    error: orgLoadError,
    isInitialLoading: orgLoading,
  } = useAsyncData<OrgSbomResult>(() => api.getOrgSbom(), {
    enabled: targetId === ALL_TARGETS,
    deps: [targetId],
  });

  async function exportOrgJson() {
    setOrgExporting(true);
    setOrgExportError(null);
    try {
      const blob = await api.exportOrgSbom();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "sbom-org-wide.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setOrgExportError(
        e instanceof Error ? e.message : "organization SBOM export failed",
      );
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
    enabled: targetId !== null && targetId !== ALL_TARGETS,
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

  // Trivy's existing CVE scan already produces real Finding rows with
  // tool="trivy" and a populated cve_id -- OSS/dependency vulnerabilities
  // aren't a new concept, so we filter the existing findings API rather than
  // standing up a parallel endpoint.
  const { data: ossFindings, isInitialLoading: ossLoading } = useAsyncData<Finding[]>(
    () =>
      api
        .findings({ target_id: targetId!, tool: "trivy", page_size: 500 })
        .then((res) => res.items.filter((f) => !!f.cve_id)),
    { enabled: targetId !== null && targetId !== ALL_TARGETS, deps: [targetId] },
  );
  const ossTotal = ossFindings?.length ?? 0;

  async function run() {
    if (targetId === null) return;
    const runTargetId = targetId;
    setRunning(true);
    setError(null);
    cancelPollRef.current?.();
    try {
      // POST /api/sbom/{target_id} now dispatches a Celery task and returns
      // immediately with status: "running" (#59) instead of blocking until
      // the clone+trivy scan finishes -- poll
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
      setLastScan({ targetId, new_count: res.new_count });
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
      setLastScan({ targetId, new_count: res.new_count });
    } catch (err) {
      setError(err instanceof Error ? err.message : "SBOM upload failed");
    } finally {
      setUploading(false);
    }
  }

  const showBusy = loading || running;
  const currentTarget = targets.find((t) => t.id === targetId);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          SBOM & OSS Vulnerabilities
        </h1>
        <p className="text-sm text-muted-foreground">
          Real CycloneDX SBOM generated from the target&apos;s dependency
          manifests (requirements.txt, package.json, go.mod, ...) via{" "}
          <code className="rounded bg-secondary px-1 py-0.5 text-xs">
            trivy fs --format cyclonedx
          </code>{" "}
          — no mocked or inferred data. Results are persisted, so this view
          reflects the last generation even after a reload.
        </p>
      </div>

      <DocumentGeneratorPanel
        layout="stacked"
        steps={[
          <DocGenStep key="target" n={1} label="Target">
            <TargetPicker targets={targets} value={targetId} onChange={setTargetId} allowAll />
          </DocGenStep>,
          ...(targetId !== ALL_TARGETS
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
                    "All direct dependencies discovered via trivy fs, with pinned versions",
                    "Known-vulnerable packages cross-referenced against this target's OSS Vulnerabilities tab",
                    "Package URL (purl) and ecosystem per component",
                  ]}
                />,
              ]
            : []),
        ]}
        generateLabel={targetId !== ALL_TARGETS ? "Generate SBOM" : undefined}
        onGenerate={targetId !== ALL_TARGETS ? run : undefined}
        generating={running}
        generateDisabled={targetId === null}
        extra={
          targetId !== ALL_TARGETS ? (
            <div className="flex flex-col gap-2">
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
                disabled={importingGithub || targetId === null}
              >
                {importingGithub ? "Importing..." : "Import from GitHub"}
              </Button>
              <Button
                variant="outline"
                className="w-full justify-center"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading || targetId === null}
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
          ) : (
            <Button
              variant="outline"
              className="w-full justify-center"
              onClick={exportOrgJson}
              disabled={orgExporting || !orgSbom || orgSbom.components.length === 0}
            >
              {orgExporting ? "Exporting..." : "Export Org SBOM (JSON)"}
            </Button>
          )
        }
      />

      {targetId === ALL_TARGETS && (
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            Aggregated from every already-scanned target&apos;s persisted SBOM
            (default branch) — read-only, no new scans are triggered here.
          </p>

          {orgDisplayError && <p className="text-sm text-destructive">{orgDisplayError}</p>}

          {orgLoading && <SkeletonList count={4} />}

          {!orgLoading && orgSbom && (
            <>
              <div className="flex flex-wrap gap-4">
                <Card className="border-border bg-card">
                  <CardContent className="px-4 py-2.5">
                    <p className="text-xs text-muted-foreground">
                      Targets with SBOM
                    </p>
                    <p className="text-lg font-semibold text-foreground">
                      {orgSbom.targets_with_sbom_count} /{" "}
                      {orgSbom.total_targets_count}
                    </p>
                  </CardContent>
                </Card>
                <Card className="border-border bg-card">
                  <CardContent className="px-4 py-2.5">
                    <p className="text-xs text-muted-foreground">
                      Unique components
                    </p>
                    <p className="text-lg font-semibold text-foreground">
                      {orgSbom.unique_component_count}
                    </p>
                  </CardContent>
                </Card>
              </div>

              <Input
                placeholder="Search components by name..."
                value={orgSearch}
                onChange={(e) => setOrgSearch(e.target.value)}
                className="max-w-sm"
              />

              <div className="flex flex-col gap-2">
                <p className="text-sm text-muted-foreground">
                  {filteredOrgComponents.length} component
                  {filteredOrgComponents.length === 1 ? "" : "s"}
                  {orgSearch ? ` matching "${orgSearch}"` : ""}
                </p>
                {filteredOrgComponents.map((c) => (
                  <OrgSbomRow
                    key={`${c.name}@${c.version}@${c.purl}`}
                    component={c}
                  />
                ))}
                {filteredOrgComponents.length === 0 && orgSbom.components.length === 0 && (
                  <EmptyState
                    icon={Package}
                    title="No SBOM data yet"
                    description="Select a repository above and generate an SBOM to see its dependency inventory here."
                    bare
                  />
                )}
                {filteredOrgComponents.length === 0 && orgSbom.components.length > 0 && (
                  <EmptyState icon={PackageSearch} title="No components match your search" bare />
                )}
              </div>
            </>
          )}
        </div>
      )}

      {targetId !== null && targetId !== ALL_TARGETS && (
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
              OSS Vulnerabilities{ossFindings ? ` (${ossTotal})` : ""}
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
              {!showBusy && components && (
                <div className="flex flex-col gap-2">
                  <p className="text-sm text-muted-foreground">
                    {components.length} components found
                  </p>
                  {/* 1396 components on a real target -- rendering them all
                      was the single longest scroll in the app. */}
                  <ActivityPagination
                    total={components.length}
                    page={sbomPage}
                    pageSize={sbomPageSize}
                    position="top"
                  />
                  {visibleComponents.map((c) => (
                    <Card key={c.id} className="border-border bg-card">
                      <CardContent className="flex items-center justify-between px-4 py-2.5">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-sm text-foreground">
                            {c.name}
                          </span>
                          <Badge variant="outline">{c.version}</Badge>
                          {scanSummary && c.is_new && (
                            <Badge
                              variant="outline"
                              className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${NEW_BADGE_COLOR}`}
                            >
                              New
                            </Badge>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {c.package_type} · {c.purl} ·{" "}
                          {formatSince(c.first_seen)}
                        </span>
                      </CardContent>
                    </Card>
                  ))}
                  {components.length === 0 && (
                    <EmptyState
                      icon={Package}
                      title="No components recorded yet"
                      description="Generate an SBOM to scan this target's dependency manifests."
                      bare
                    />
                  )}
                </div>
              )}
            </>
          )}

          {tab === "aibom" && targetId !== null && targetId !== ALL_TARGETS && (
            <AiBomPanel targetId={targetId} targetName={currentTarget?.name} />
          )}

          {tab === "vulnerabilities" && (
            <>
              {ossLoading && <SkeletonList count={3} />}
              {!ossLoading && ossFindings && (
                <FindingsList
                  findings={ossFindings}
                  total={ossTotal}
                  page={1}
                  pageSize={Math.max(ossTotal, 1)}
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
