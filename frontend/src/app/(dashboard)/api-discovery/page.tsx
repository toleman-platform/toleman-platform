"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type Target, type ScanRun, type Endpoint } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { useAsyncData } from "@/hooks/use-async-data";
import { useScanRun } from "@/hooks/features/use-scan-run";
import { ScanProgress } from "@/components/features/scans";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AlertBanner } from "@/components/ui/alert-banner";
import { TargetPicker } from "@/components/features/targets";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { BulkActionBar } from "@/components/ui/bulk-action-bar";
import { ListRow, ListRows, SelectAllVisible } from "@/components/ui/list-row";
import { useSelection } from "@/hooks/use-selection";
import { DocGenStep, DocumentGeneratorPanel, WhatsIncludedCard } from "@/components/features/intelligence";
import { PageHeader } from "@/components/ui/page-header";
import { HelpHint } from "@/components/ui/help-hint";
import { HELP_CONTENT } from "@/lib/help-content";
import { Globe } from "lucide-react";
import { formatSince } from "@/lib/format/date";

const NEW_BADGE_COLOR = "border-chart-5/20 bg-chart-5/10 text-chart-5";
const EXCLUDED_BADGE_COLOR = "border-muted-foreground/30 bg-muted text-muted-foreground px-2 py-0.5 text-xs font-bold uppercase tracking-wide";
const FRAMEWORK_SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

/**
 * discovery.py's django/spring branch has no HTTP verb to read off a URL
 * conf (Django's urls.py and a bare Spring @RequestMapping don't carry one),
 * so it always emits method "-"; its django regex also accepts a
 * zero-length capture, so it can match a route of "". That same permissive
 * branch is what matched a bare `path("...")` call inside
 * backend/tests/test_runner.py in production -- not a route registration at
 * all -- and tagged it "django" in a FastAPI codebase. All three symptoms
 * (the "-" method, the empty route, the "..." route) share this one cause,
 * so one predicate catches all of them: a row with no real method or no
 * real route is not the "route with file:line provenance" this page's own
 * copy promises, and is dropped before it renders rather than shown as if
 * it were one.
 */
function isExtractionArtefact(e: Pick<Endpoint, "method" | "route">): boolean {
  const route = e.route.trim();
  // Deliberately NOT keyed on `method === "-"`. That reads like a placeholder
  // but is a real value: backend/app/scanners/discovery.py's django and spring
  // branches both fall through to `method, route = "-", groups[0]`, because
  // neither framework encodes the HTTP method at the route declaration. Those
  // are genuine endpoints with an unknown method, and filtering on "-" would
  // have silently deleted every Django and Spring route the scanner found --
  // hiding real API surface while the page claimed to list all of it.
  //
  // What makes a row an artefact is the ROUTE: a regex that matched but
  // captured nothing usable. A route is the one field every framework
  // populates, so its absence is unambiguous.
  return route === "" || route === "..." || route === "-";
}

const METHOD_ORDER = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function methodRank(method: string): number {
  const idx = METHOD_ORDER.indexOf(method.toUpperCase());
  return idx === -1 ? METHOD_ORDER.length : idx;
}

/**
 * Endpoints grouped by HTTP method (conventional verb order, then anything
 * else alphabetically) -- the axis someone actually scans this table by
 * ("what can POST to this service") -- with each group's rows sorted by
 * route so two registrations of the same path land next to each other. The
 * file:line is the only thing that tells them apart; adjacency is what
 * makes that legible instead of two identical-looking rows 40 apart.
 */
function groupByMethod(endpoints: Endpoint[]): { method: string; items: Endpoint[] }[] {
  const groups = new Map<string, Endpoint[]>();
  for (const e of endpoints) {
    const list = groups.get(e.method);
    if (list) list.push(e);
    else groups.set(e.method, [e]);
  }
  return Array.from(groups.entries())
    .sort(([a], [b]) => methodRank(a) - methodRank(b) || a.localeCompare(b))
    .map(([method, items]) => ({
      method,
      items: [...items].sort(
        (x, y) => x.route.localeCompare(y.route) || x.file.localeCompare(y.file) || x.line - y.line,
      ),
    }));
}

export default function ApiDiscoveryPage() {
  const [chosenTargetId, setChosenTargetId] = useState<number | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // "" means no facet: every framework shown. A specific value narrows the
  // grouped table below to routes discovery attributed to that one
  // framework, so a misattribution (or a target that mixes frameworks) can
  // be isolated instead of scrolled past.
  const [frameworkFilter, setFrameworkFilter] = useState<string>("");

  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets());
  const targets = targetsData ?? [];
  const targetId = chosenTargetId ?? targets[0]?.id ?? null;
  const setTargetId = setChosenTargetId;
  // Only meaningful relative to a scan just triggered in this session; the
  // plain GET on load always reports is_new: false, so we don't show the
  // "New" column at all until a POST has completed here.
  // Tagged with the target it describes rather than cleared by an effect on
  // target change: a "new endpoints" count belonging to a different repo is
  // worse than no count at all.
  const [lastRun, setLastRun] = useState<{ targetId: number; new_count: number } | null>(null);
  const cancelPollRef = useRef<(() => void) | null>(null);

  // Issue #72: Active API Scanning against the endpoints listed above.
  const scanTargetRef = useRef<number | null>(null);
  const [apiScanError, setApiScanError] = useState<string | null>(null);
  const [apiScanResult, setApiScanResult] = useState<{ targetId: number; scan: ScanRun } | null>(null);
  const apiScan = useScanRun({
    onCompleted: () => {
      // Re-read the persisted latest scan rather than keeping the polled
      // copy: it is the same row, and one owner beats two.
      const id = scanTargetRef.current;
      if (id !== null) void api.getLatestApiScan(id).then((res) => setApiScanResult({ targetId: id, scan: res.scan! }));
    },
    onFailed: (message) => setApiScanError(message),
  });
  const apiScanRunning = apiScan.phase === "queued" || apiScan.phase === "running";
  const currentTarget = targets.find((t) => t.id === targetId) ?? null;

  useEffect(() => {
    // Stop the discovery poll if the component unmounts mid-run. The active
    // API scan cleans up its own poll inside useScanRun.
    return () => cancelPollRef.current?.();
  }, []);

  // A framework facet left over from the previous repo would otherwise
  // silently render "0 routes" for the new one the instant it has no route
  // under that framework, which reads as "discovery found nothing" rather
  // than "your old filter doesn't apply here".
  //
  // Reset during render rather than in an effect: eslint-plugin-react-hooks v7
  // errors on a setState called synchronously in an effect body
  // (set-state-in-effect) and CI runs --max-warnings=0. The deeper reason is
  // that the effect version paints one frame with the previous repo's filter
  // still applied before correcting itself; this is the adjusting-state-on-
  // prop-change pattern React documents for exactly this case.
  const [prevTargetId, setPrevTargetId] = useState(targetId);
  if (prevTargetId !== targetId) {
    setPrevTargetId(targetId);
    setFrameworkFilter("");
  }

  const {
    data: persisted,
    error: loadError,
    isInitialLoading: loading,
    refetch: reloadPersisted,
  } = useAsyncData(
    () =>
      Promise.all([api.getDiscoveredEndpoints(targetId!), api.getLatestApiScan(targetId!)]).then(
        ([res, latest]) => ({ endpoints: res.endpoints, latestScan: latest.scan }),
      ),
    { enabled: targetId !== null, deps: [targetId] },
  );
  // Extraction noise (see isExtractionArtefact) is filtered once, here, so
  // every consumer below -- the count, the facet options, the selectable
  // ids, the grouped table -- agrees on what a "discovered endpoint" is
  // instead of each re-deriving it and risking disagreement.
  const endpoints = useMemo(
    () => persisted?.endpoints?.filter((e) => !isExtractionArtefact(e)) ?? null,
    [persisted],
  );
  // Every framework discovery attributed for this target, offered as a
  // facet rather than a second grouping axis: the ask groups by method (how
  // someone actually scans this table -- "what can POST to this service"),
  // and lets framework, which is attribution rather than a property of the
  // route, narrow the list instead of splintering it into extra sections.
  const frameworks = useMemo(
    () => Array.from(new Set((endpoints ?? []).map((e) => e.framework))).sort(),
    [endpoints],
  );
  const facetedEndpoints = useMemo(
    () => (endpoints ?? []).filter((e) => frameworkFilter === "" || e.framework === frameworkFilter),
    [endpoints, frameworkFilter],
  );
  // Excluded endpoints are deliberately not selectable: the backend refuses
  // to scan them even when they are named explicitly (#469), so offering a
  // checkbox would let someone tick a row and watch nothing happen.
  //
  // Scoped to the facet, not to every endpoint: SelectAllVisible's own
  // contract is "act only on what the user can see" (see useSelection's doc
  // comment), and a facet hiding 90 Express routes while this list still
  // named them would let "select all" tick rows nothing on screen
  // represents.
  const endpointIds = useMemo(
    () => facetedEndpoints.filter((e) => !e.excluded).map((e) => e.id),
    [facetedEndpoints],
  );
  const [scopeBusyId, setScopeBusyId] = useState<number | null>(null);

  async function toggleScope(endpoint: { id: number; excluded: boolean }) {
    if (targetId === null) return;
    setScopeBusyId(endpoint.id);
    setError(null);
    try {
      await api.setEndpointScope(targetId, endpoint.id, !endpoint.excluded);
      await reloadPersisted();
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not change this endpoint's scope");
    } finally {
      setScopeBusyId(null);
    }
  }
  const selection = useSelection(endpointIds);
  useEffect(() => {
    // Narrowing the facet can hide a row the reader had ticked without
    // hiding the tick: `selection.selectedIds` isn't bounded by what's on
    // screen (see runApiScan below), so an old selection would otherwise
    // still be sitting there, invisible, ready to be scanned by a click on
    // a button whose count no longer reflects it.
    selection.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [frameworkFilter]);
  const groupedByMethod = useMemo(() => groupByMethod(facetedEndpoints), [facetedEndpoints]);
  const scanSummary = lastRun && lastRun.targetId === targetId ? lastRun : null;
  // A scan just run in this session wins over the persisted "latest scan";
  // both are keyed to their target so switching repos never shows another
  // repo's result.
  const lastApiScan =
    apiScanResult && apiScanResult.targetId === targetId
      ? apiScanResult.scan
      : (persisted?.latestScan ?? null);

  async function run() {
    if (targetId === null) return;
    const runTargetId = targetId;
    setRunning(true);
    setError(null);
    cancelPollRef.current?.();
    try {
      // POST /api/discovery/{target_id} now dispatches a Celery task and
      // returns immediately with status: "running" (#59) instead of
      // blocking until the clone+grep finishes; poll
      // GET /api/discovery/{target_id}/runs/{run_id} until it's done.
      const dispatch = await api.runDiscovery(runTargetId);
      cancelPollRef.current = pollUntilSettled(
        () => api.getDiscoveryRun(runTargetId, dispatch.run_id),
        (run) => {
          if (run.status === "completed") {
            // Refetch rather than writing `run.endpoints` in directly: the
            // persisted list stays the single owner, so the loading state and
            // what is on screen cannot disagree.
            reloadPersisted();
            setLastRun({ targetId: runTargetId, new_count: run.new_count });
            setRunning(false);
          } else if (run.status === "failed") {
            setError(run.error || "discovery failed");
            setRunning(false);
          }
        },
        {
          onError: (e) => {
            setError(e instanceof Error ? e.message : "discovery failed");
            setRunning(false);
          },
        },
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "discovery failed");
      setRunning(false);
    }
  }

  // Non-null only while a framework facet is actively hiding endpoints: then
  // "scan all" (nothing selected) has to mean all of what the facet is
  // showing, not the server's literal everything, and the label below says
  // the real count instead of "all" quietly meaning something narrower than
  // it reads.
  const scanAllCount = frameworkFilter !== "" ? endpointIds.length : null;

  async function runApiScan() {
    if (targetId === null) return;
    const scanTargetId = targetId;
    scanTargetRef.current = scanTargetId;
    setApiScanError(null);
    apiScan.reset();
    try {
      // POST /api/api-scan/{target_id} dispatches a Celery task (nuclei
      // against already-discovered endpoints) and returns immediately
      // (#72, same async pattern as runScan/runDiscovery). Issue #212: the
      // poll, the elapsed counter and the ETA now come from useScanRun, so
      // a DAST run (which is typically the longest-running scan here)
      // reports progress the same way a SAST run does instead of showing a
      // bare "Scanning...".
      //
      // `undefined` asks the server to resolve every in-scope endpoint for
      // the target itself, its own source of truth rather than a client
      // snapshot -- correct only when nothing here is hidden. Once a
      // framework facet narrows what's on screen, "scan all" has to mean
      // all of what the facet is showing (`endpointIds`), or a click meant
      // to scan the visible FastAPI routes would reach past them into every
      // Express route the facet just hid.
      const dispatch = await api.runApiScan(
        scanTargetId,
        selection.count > 0 ? selection.selectedIds : (scanAllCount !== null ? endpointIds : undefined),
      );
      apiScan.track(dispatch.scan_id);
    } catch (e) {
      apiScan.fail(e instanceof Error ? e.message : "active scan failed to start");
    }
  }

  const showBusy = loading || running;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="API Discovery"
        description="Static route extraction over the target's source (Flask/FastAPI/Express/Gin/Django/Spring patterns), real grep matches with file:line provenance, not an inferred/mocked inventory. Results are persisted, so this view reflects the last scan even after a reload."
        badge={<HelpHint topic={HELP_CONTENT["api-discovery"]} />}
      />

      <DocumentGeneratorPanel
        layout="stacked"
        steps={[
          <DocGenStep key="target" n={1} label="Target">
            <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />
          </DocGenStep>,
          ...(currentTarget
            ? [
                <DocGenStep key="scope" n={2} label="Scope">
                  <div className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground">
                    Default branch ({currentTarget.default_branch})
                  </div>
                </DocGenStep>,
                <WhatsIncludedCard
                  key="included"
                  items={[
                    "Every route discovered via static regex extraction (Flask/FastAPI/Express/Gin/Django/Spring patterns), grouped by method",
                    "File:line provenance for each discovered route",
                    "New-since-last-scan endpoints flagged",
                  ]}
                />,
              ]
            : []),
        ]}
        generateLabel="Run Discovery"
        onGenerate={run}
        generating={running}
        generateDisabled={targetId === null}
      />

      {error && <p className="text-sm text-destructive">{error}</p>}

      {!error && !loadError && scanSummary && (
        <p className="text-sm text-foreground">
          {scanSummary.new_count > 0
            ? `${scanSummary.new_count} new endpoint${scanSummary.new_count === 1 ? "" : "s"} found`
            : "No new endpoints"}
        </p>
      )}

      {showBusy && <SkeletonList count={3} />}

      {!showBusy && endpoints && (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">
              {endpoints.length} endpoint{endpoints.length === 1 ? "" : "s"} found
              {frameworkFilter && ` · ${facetedEndpoints.length} shown`}
            </p>
            <div className="flex flex-wrap items-center gap-3">
              {frameworks.length > 1 && (
                <select
                  aria-label="Filter by framework"
                  className={FRAMEWORK_SELECT_CLASS}
                  value={frameworkFilter}
                  onChange={(e) => setFrameworkFilter(e.target.value)}
                >
                  <option value="">All frameworks</option>
                  {frameworks.map((f) => (
                    <option key={f} value={f}>
                      {f}
                    </option>
                  ))}
                </select>
              )}
              {endpoints.length > 0 && (
                <SelectAllVisible
                  allSelected={selection.allVisibleSelected}
                  someSelected={selection.someVisibleSelected}
                  onChange={selection.toggleAllVisible}
                />
              )}
            </div>
          </div>

          {/* BulkActionBar renders null at count === 0 (bulk-action-bar.tsx),
              so every no-selection branch of the label below was unreachable:
              "Scan N shown" and "Scan all" could not appear at all, and the
              only way to start a scan was to tick a row first. The scan-all
              action is not a bulk action -- it is the page's primary verb --
              so it renders on its own when nothing is selected, and hands over
              to the bar once a selection exists. */}
          {endpoints.length > 0 && selection.count === 0 && (
            <div className="flex justify-end">
              <Button
                size="sm"
                onClick={runApiScan}
                disabled={apiScanRunning || !currentTarget?.api_base_url || scanAllCount === 0}
              >
                {apiScanRunning
                  ? "Scanning..."
                  : scanAllCount !== null
                    ? `Scan ${scanAllCount} shown for vulnerabilities`
                    : "Scan all for vulnerabilities"}
              </Button>
            </div>
          )}

          {endpoints.length > 0 && (
            <BulkActionBar
              count={selection.count}
              itemNoun="endpoint"
              onClear={selection.clear}
              actions={[
                {
                  label: apiScanRunning
                    ? "Scanning..."
                    : `Scan ${selection.count} selected for vulnerabilities`,
                  onClick: runApiScan,
                  disabled: apiScanRunning || !currentTarget?.api_base_url,
                },
              ]}
            >
              {!currentTarget?.api_base_url && (
                <span className="text-xs text-muted-foreground">
                  Set this target&apos;s API base URL on its{" "}
                  <Link href={`/targets/${targetId}`} className="underline">
                    detail page
                  </Link>{" "}
                  first.
                </span>
              )}
            </BulkActionBar>
          )}

          {apiScanRunning && apiScan.phase && (
            <ScanProgress
              phase={apiScan.phase}
              tool="api-scan"
              elapsedSeconds={apiScan.elapsedSeconds}
              etaSeconds={apiScan.etaSeconds}
            />
          )}

          {apiScanError && <p className="text-xs text-destructive">{apiScanError}</p>}

          {lastApiScan && !apiScanRunning && (
            lastApiScan.status === "failed" ? (
              // A failure used to be a plain <p>, indistinguishable from the
              // "N findings" sentence above it -- same weight, same color,
              // same silence to a screen reader, the same problem (core H5)
              // fixed for bulk scan dispatch in scans-list.tsx. AlertBanner
              // is the one honest-failure primitive this codebase already
              // has (see finding-detail-drawer.tsx's Triage Failed), reused
              // here rather than re-invented.
              <AlertBanner tone="critical" title="Last active scan failed">
                {lastApiScan.error_message || "The scan did not complete."}
              </AlertBanner>
            ) : (
              <p className="text-xs text-foreground">
                {lastApiScan.status === "completed"
                  ? `Last active scan: ${lastApiScan.findings_count} finding${lastApiScan.findings_count === 1 ? "" : "s"} (tool=api-scan)`
                  : `Last active scan: ${lastApiScan.status}`}
                {lastApiScan.status === "completed" && lastApiScan.findings_count > 0 && targetId !== null && (
                  <>
                    {" · "}
                    <Link href={`/targets/${targetId}`} className="underline">
                      view findings
                    </Link>
                  </>
                )}
              </p>
            )
          )}

          {groupedByMethod.map(({ method, items }) => (
            <div key={method} className="flex flex-col gap-1.5">
              <div className="flex items-center gap-2 px-1">
                <Badge variant="outline" className="font-mono text-[11px]">
                  {method}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  {items.length} route{items.length === 1 ? "" : "s"}
                </span>
              </div>
              <ListRows>
                {items.map((e) => (
                  <ListRow key={e.id}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${e.method} ${e.route}`}
                      className="h-4 w-4 shrink-0 accent-primary"
                      checked={selection.isSelected(e.id)}
                      disabled={e.excluded}
                      onChange={(ev) => selection.toggle(e.id, ev.target.checked)}
                    />
                    <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                      <span
                        className={`truncate font-mono text-sm ${e.excluded ? "text-muted-foreground line-through" : "text-foreground"}`}
                        title={e.route}
                      >
                        {e.route}
                      </span>
                      {e.excluded && (
                        <Badge variant="outline" className={EXCLUDED_BADGE_COLOR} title={e.exclusion_reason ?? undefined}>
                          Out of scope
                        </Badge>
                      )}
                      {scanSummary && e.is_new && (
                        <Badge variant="outline" className={`px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${NEW_BADGE_COLOR}`}>
                          New
                        </Badge>
                      )}
                    </div>
                    {/* file:line used to be the least-styled part of a row that
                        crammed framework, provenance and age into one grey
                        string -- the exact detail a reader needs to tell two
                        same-route rows apart, given the least contrast to see
                        it with. It gets its own slot, in the foreground color,
                        rather than competing with its neighbors for attention. */}
                    <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-0.5 text-xs">
                      <span className="text-muted-foreground">{e.framework}</span>
                      <span className="whitespace-nowrap font-mono text-foreground" title={`${e.file}:${e.line}`}>
                        {e.file}:{e.line}
                      </span>
                      <span className="text-muted-foreground">{formatSince(e.first_seen)}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={scopeBusyId === e.id}
                      onClick={() => toggleScope(e)}
                      title={
                        e.excluded
                          ? "Allow active scans to probe this endpoint again"
                          : "Never probe this endpoint in an active scan"
                      }
                    >
                      {e.excluded ? "Bring into scope" : "Exclude"}
                    </Button>
                  </ListRow>
                ))}
              </ListRows>
            </div>
          ))}
          {endpoints.length > 0 && facetedEndpoints.length === 0 && (
            <p className="px-1 text-sm text-muted-foreground">
              No routes match the &quot;{frameworkFilter}&quot; filter.
            </p>
          )}
          {endpoints.length === 0 && (
            <EmptyState
              icon={Globe}
              title="No routes discovered yet"
              description="Run discovery to scan this target's codebase for API routes."
              action={
                <Button size="sm" onClick={run} disabled={running || targetId === null}>
                  {running ? "Scanning..." : "Run Discovery"}
                </Button>
              }
            />
          )}
        </div>
      )}
    </div>
  );
}
