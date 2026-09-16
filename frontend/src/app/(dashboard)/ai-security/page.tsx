"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Bot, Boxes, Radar } from "lucide-react";
import { api, type Target, type ScanSummary } from "@/lib/api";
import { pollUntilSettled } from "@/lib/poll";
import { getErrorMessage } from "@/std-lib";
import { useActiveScans } from "@/hooks/features/use-active-scans";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWriteAction } from "@/hooks/use-write-action";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { useScanRun } from "@/hooks/features/use-scan-run";
import { ScanHealthBadge, ScanProgress } from "@/components/features/scans";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonList } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/ui/page-header";
import { HelpHint } from "@/components/ui/help-hint";
import { HELP_CONTENT } from "@/lib/help-content";
import { AlertBanner } from "@/components/ui/alert-banner";
import { PartialFailureBanner } from "@/components/ui/partial-failure-banner";
import { TargetPicker } from "@/components/features/targets";
import { AiBomPanel } from "@/components/features/intelligence";

// Issue #224: AI/ML repo detection (#185), ModelScan (#186) and the LLM
// SAST ruleset (#189) shipped with zero dedicated frontend surface; the
// only way to see any of it was to already know to look at a target's
// Vulnerabilities tab and filter by tool by hand. This page is the entry
// point: which repos got flagged, what those two AI-specific scanners
// found in them, and a way to pull the AI Bill of Materials without a
// detour through the SBOM page.
//
// A later pass (this one) removed the "not yet available" placeholder that
// used to sit under this: a visible dead section is a confidence problem on
// a page whose whole job is establishing AI/ML posture, and every other
// element here now actually goes somewhere. garak (#191) still has no
// TOOL_COMMANDS entry -- it needs a live model endpoint to probe, not a repo
// checkout -- so LLM red-teaming stays absent from this page rather than
// asserted and then apologized for.
type AiTool = "modelscan" | "semgrep-llm";

const TOOL_LABEL: Record<AiTool, string> = {
  modelscan: "ModelScan",
  "semgrep-llm": "LLM rules",
};

// The two scanners this page is about, in the order their columns read.
// Both are members of lib/scan-tools.ts's SCAN_TOOLS; this is the AI subset
// of it, not a second list of tools the platform can run.
const AI_TOOLS: readonly AiTool[] = ["modelscan", "semgrep-llm"];

const DEACTIVATED_TITLE = "This target is deactivated; scanning is off. Reactivate it on the target page.";

export default function AiSecurityPage() {
  const { activeWorkspaceId } = useWorkspaceContext();
  const {
    data: targetsRaw,
    error: targetsError,
    isInitialLoading: targetsLoading,
    refetch: refetchTargets,
  } = useAsyncData<Target[]>(() => api.targets({ workspace_id: activeWorkspaceId }), {
    deps: [activeWorkspaceId],
  });
  // (#520) Workspace-scoped, same pattern as sbom/page.tsx: filtered again
  // client-side to cover the window where a workspace switch's refetch is
  // still in flight and useAsyncData is still showing the previous
  // workspace's targets.
  const targets = (targetsRaw ?? []).filter(
    (t) => activeWorkspaceId === null || t.workspace_id === activeWorkspaceId,
  );

  // Per-target "which tools have ever run" (backend/app/api/scans.py's
  // scans_summary: one row per (target, tool) EVER completed, not just the
  // latest run). This is the only way to tell a repo ModelScan hasn't
  // reached yet from one it reached and cleared -- both currently produce
  // "0 ModelScan findings" from the findings fetch below, and those are not
  // the same fact.
  const {
    data: scanSummary,
    error: scanSummaryError,
    isInitialLoading: scanSummaryLoading,
    refetch: refetchScanSummary,
  } = useAsyncData<ScanSummary>(() => api.scanSummary());

  // Two org-wide queries, one per AI-specific tool, then grouped by target
  // client-side; the same shape sbom/page.tsx already uses for its OSS
  // Vulnerabilities tab (fetchFindings({ tool, page_size: 500 })). No
  // dedicated aggregate endpoint exists yet, and these two tools only ever
  // run against the handful of AI-flagged repos, so this stays cheap.
  //
  // `resolved: false` is deliberate, not a default: every badge and counter
  // below links straight into /findings, and that page's queues (see
  // lib/findings-view.ts) only ever narrow to open or to resolved, never
  // both at once. Counting open+resolved here while the destination shows
  // open-only is exactly the "number and the list behind it disagree" bug
  // this page exists to not have.
  const {
    data: modelscanFindings,
    error: modelscanError,
    isInitialLoading: modelscanLoading,
    refetch: refetchModelscan,
  } = useAsyncData(
    () => api.findings({ tool: "modelscan", resolved: false, page_size: 500 }).then((r) => r.items)
  );
  const {
    data: semgrepLlmFindings,
    error: semgrepLlmError,
    isInitialLoading: semgrepLlmLoading,
    refetch: refetchSemgrepLlm,
  } = useAsyncData(
    () => api.findings({ tool: "semgrep-llm", resolved: false, page_size: 500 }).then((r) => r.items)
  );

  const loading = targetsLoading || modelscanLoading || semgrepLlmLoading || scanSummaryLoading;
  // Server-side truth about what is already running, so the row does not
  // offer a duplicate dispatch of a scan someone started elsewhere.
  const { isTargetScanning, refresh: refreshActiveScans } = useActiveScans();

  const aiTargets = (targets ?? []).filter((t) => t.is_ai_repo_effective);

  function countFor(tool: AiTool, targetId: number): number {
    const findings = tool === "modelscan" ? modelscanFindings : semgrepLlmFindings;
    return (findings ?? []).filter((f) => f.target_id === targetId).length;
  }

  // `scanSummary[id]` is only absent because the target was never scanned
  // by anything, or because the fetch itself failed -- see
  // target-overview.tsx's identical `countsUnknown`/`scanUnknown` split. Only
  // trust an absence once the fetch is known to have actually succeeded.
  const scanSummaryReady = scanSummary !== null && !scanSummaryError;
  function everScanned(tool: AiTool, targetId: number): boolean {
    return (scanSummary?.[String(targetId)]?.tools ?? []).includes(tool);
  }

  function aggregateUnknownHint(tool: AiTool, count: number): string | undefined {
    if (count > 0) return undefined; // a positive count is proof the tool ran; nothing to caveat.
    const scannedCount = aiTargets.filter((t) => everScanned(tool, t.id)).length;
    if (scanSummaryReady && aiTargets.length > 0 && scannedCount === 0) {
      return `no AI/ML repo has been scanned by ${TOOL_LABEL[tool]} yet`;
    }
    return undefined;
  }

  function aggregateHint(tool: AiTool, count: number, base: string): string {
    if (count > 0 || !scanSummaryReady || aiTargets.length === 0) return base;
    const scannedCount = aiTargets.filter((t) => everScanned(tool, t.id)).length;
    // Zero across some, but not all, AI repos is a real measurement, just a
    // partial one; say so rather than let a bare "0" imply full coverage.
    if (scannedCount > 0 && scannedCount < aiTargets.length) {
      return `${base} - measured across ${scannedCount} of ${aiTargets.length} AI/ML repos scanned`;
    }
    return base;
  }

  // AI Bill of Materials: which AI-flagged target(s) the panel(s) below show.
  // Falls back to the first AI target rather than tracking "unset" as a
  // separate state -- with 0 AI targets this is never read (the section
  // renders its own empty state first), and with exactly 1 there is nothing
  // to pick.
  const [aibomTargetIds, setAibomTargetIds] = useState<number[]>([]);
  const selectedAibomTargets = aiTargets.filter((t) => aibomTargetIds.includes(t.id));
  const aibomTargets = selectedAibomTargets.length > 0 ? selectedAibomTargets : aiTargets.slice(0, 1);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="AI Security"
        description="Repositories detected as using AI/ML, and vulnerability findings from ModelScan and LLM rulesets."
        badge={<HelpHint topic={HELP_CONTENT["ai-security"]} />}
      />

      <PartialFailureBanner
        sources={[
          {
            label: "AI/ML repo list",
            failed: !!targetsError,
            consequence: "The repo count and list below, and the AI Bill of Materials repository picker, may be missing repos.",
          },
          {
            label: "Scan history",
            failed: !!scanSummaryError,
            consequence: "A 0 finding count cannot be told apart from a repo that was never scanned.",
          },
          {
            label: "ModelScan findings",
            failed: !!modelscanError,
            consequence: "The ModelScan counter and per-repo badges are not shown.",
          },
          {
            label: "LLM ruleset findings",
            failed: !!semgrepLlmError,
            consequence: "The LLM ruleset counter and per-repo badges are not shown.",
          },
        ]}
        action={
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              refetchTargets();
              refetchScanSummary();
              refetchModelscan();
              refetchSemgrepLlm();
            }}
          >
            Try again
          </Button>
        }
      />

      <StatGrid columns={3}>
        <StatCard
          label="AI/ML repos"
          value={aiTargets.length}
          hint="detected via dependency manifests"
          icon={Bot}
          unknown={targetsLoading || !!targetsError}
          unknownHint={targetsError ? "repo list unavailable" : undefined}
          // A single flagged repo IS the answer to "which one" -- send the
          // click straight there instead of down to a one-row list. With
          // more than one, the destination is the list this same page
          // already renders below.
          href={
            aiTargets.length === 1
              ? `/targets/${aiTargets[0].id}`
              : aiTargets.length > 1
                ? "#ai-flagged-repos"
                : undefined
          }
        />
        <StatCard
          label="ModelScan findings"
          value={(modelscanFindings ?? []).length}
          hint={aggregateHint("modelscan", (modelscanFindings ?? []).length, "unsafe deserialization in serialized model files")}
          icon={Boxes}
          tone={(modelscanFindings ?? []).length > 0 ? "attention" : "default"}
          unknown={modelscanLoading || !!modelscanError || !!aggregateUnknownHint("modelscan", (modelscanFindings ?? []).length)}
          unknownHint={modelscanError ? "ModelScan findings unavailable" : aggregateUnknownHint("modelscan", (modelscanFindings ?? []).length)}
          href="/findings?tool=modelscan&queue=all"
        />
        <StatCard
          label="LLM ruleset findings"
          value={(semgrepLlmFindings ?? []).length}
          hint={aggregateHint("semgrep-llm", (semgrepLlmFindings ?? []).length, "OWASP LLM Top 10 (unsafe eval/shell sinks, unpinned models)")}
          icon={Radar}
          tone={(semgrepLlmFindings ?? []).length > 0 ? "attention" : "default"}
          unknown={semgrepLlmLoading || !!semgrepLlmError || !!aggregateUnknownHint("semgrep-llm", (semgrepLlmFindings ?? []).length)}
          unknownHint={semgrepLlmError ? "LLM ruleset findings unavailable" : aggregateUnknownHint("semgrep-llm", (semgrepLlmFindings ?? []).length)}
          href="/findings?tool=semgrep-llm&queue=all"
        />
      </StatGrid>

      <div id="ai-flagged-repos" className="flex flex-col gap-3 scroll-mt-4">
        <h2 className="text-sm font-medium text-foreground">AI/ML-flagged repos</h2>

        {loading && <SkeletonList count={3} />}

        {!loading && aiTargets.length === 0 && (
          <EmptyState
            icon={Bot}
            title="No AI/ML repos detected yet"
            description="A target is flagged automatically when its dependency manifests reference AI/ML packages (PyTorch, transformers, langchain, and similar); or set manually from its Settings tab."
          />
        )}

        {!targetsLoading &&
          aiTargets.map((t) => (
            <Card key={t.id} className="border-border bg-card">
              <CardContent className="flex flex-col gap-3 px-4 py-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Link href={`/targets/${t.id}`} className="truncate font-medium text-foreground hover:underline">
                        {t.name}
                      </Link>
                      <Badge variant="outline" className="shrink-0 text-[10px]">
                        AI/ML
                      </Badge>
                    </div>
                    {t.is_ai_repo_signals && (
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">{t.is_ai_repo_signals}</p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2 text-xs">
                    <ToolBadge tool="modelscan" target={t} count={countFor("modelscan", t.id)} scanned={everScanned("modelscan", t.id)} scanSummaryReady={scanSummaryReady} findingsFailed={!!modelscanError} />
                    <ToolBadge tool="semgrep-llm" target={t} count={countFor("semgrep-llm", t.id)} scanned={everScanned("semgrep-llm", t.id)} scanSummaryReady={scanSummaryReady} findingsFailed={!!semgrepLlmError} />
                  </div>
                </div>

                <RepoScanActions
                  target={t}
                  alreadyScanning={isTargetScanning(t.id)}
                  onDispatched={refreshActiveScans}
                  onScanCompleted={() => {
                    // The badges above are computed from the findings and
                    // scan-history queries, neither of which knows a scan
                    // just landed. Refetched on completion so a repo that
                    // read "not scanned" a moment ago stops saying so.
                    refetchScanSummary();
                    refetchModelscan();
                    refetchSemgrepLlm();
                  }}
                />
              </CardContent>
            </Card>
          ))}
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-sm font-medium text-foreground">AI Bill of Materials</h2>
          {aiTargets.length > 1 && (
            <TargetPicker
              targets={aiTargets}
              value={aibomTargetIds}
              onChange={setAibomTargetIds}
              label="AI/ML repositories"
            />
          )}
        </div>

        {targetsLoading ? (
          // Gated on the repo fetch specifically, not `loading`: this
          // section only needs to know which targets are AI-flagged, and
          // waiting on the two findings queries too would hold a working
          // generate button hostage to an unrelated request.
          <SkeletonList count={1} />
        ) : aiTargets.length === 0 ? (
          <EmptyState
            icon={Boxes}
            title="No AI/ML repos to bill yet"
            description="Once a repo is flagged as AI/ML, its models and datasets can be extracted and exported here."
          />
        ) : (
          <div className="flex flex-col gap-4">
            {aibomTargets.map((t) => (
              <AiBomGeneratePanel key={t.id} target={t} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * One repo's AI Bill of Materials: generate button, its own dispatch-then-poll
 * state, and the panel itself. Split out from AiSecurityPage so picking
 * several AI/ML repos above renders one of these per repo rather than one
 * generation running for whichever repo happened to be selected last.
 */
function AiBomGeneratePanel({ target }: { target: Target }) {
  // Bumped on a completed generation to force AiBomPanel to remount and
  // refetch -- its own useAsyncData only keys off targetId, which does not
  // change when the user regenerates the same repo's AIBOM.
  const [generation, setGeneration] = useState(0);
  const cancelPollRef = useRef<(() => void) | null>(null);
  const generateAction = useWriteAction("AI Bill of Materials generation failed");

  // Same unmount guard as sbom/page.tsx's `run()`: a poll left running past
  // navigation would resolve/reject into a component that no longer exists.
  useEffect(() => {
    return () => {
      cancelPollRef.current?.();
    };
  }, []);

  async function generateAiBom() {
    const targetId = target.id;
    await generateAction.run(
      () =>
        new Promise<void>((resolve, reject) => {
          // Same dispatch-then-poll shape as sbom/page.tsx's `run()`: POST
          // /api/sbom/{id} returns immediately with a run id, and the AIBOM
          // rows are upserted server-side as part of that same task (see
          // backend/app/tasks/sbom_tasks.py's extract_ai_components call) --
          // there is no separate "generate AIBOM" endpoint to call instead.
          api
            .generateSbom(targetId)
            .then((dispatch) => {
              cancelPollRef.current?.();
              cancelPollRef.current = pollUntilSettled(
                () => api.getSbomRun(targetId, dispatch.run_id),
                (run) => {
                  if (run.status === "completed") {
                    setGeneration((g) => g + 1);
                    resolve();
                  } else if (run.status === "failed") {
                    reject(new Error(run.error || "AI Bill of Materials generation failed"));
                  }
                },
                { onError: reject },
              );
            })
            .catch(reject);
        }),
    );
  }

  const deactivated = target.is_active === false;

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-3 px-4 py-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">
            Models and datasets {target.name} depends on, extracted from the same checkout as its SBOM.
            Generating refreshes both.
          </p>
          <Button
            size="sm"
            variant="outline"
            className="h-7 shrink-0 text-xs"
            onClick={generateAiBom}
            disabled={generateAction.submitting || deactivated}
            title={deactivated ? DEACTIVATED_TITLE : undefined}
          >
            {generateAction.submitting ? "Generating..." : "Generate AI Bill of Materials"}
          </Button>
        </div>

        {deactivated && (
          <p className="text-xs text-warning">
            This target is deactivated; scanning is off, so generating a new AI Bill of Materials is
            disabled. The one already on file stays readable and exportable.
          </p>
        )}

        {generateAction.error && <AlertBanner tone="critical">{generateAction.error}</AlertBanner>}

        <AiBomPanel key={`${target.id}-${generation}`} targetId={target.id} targetName={target.name} />
      </CardContent>
    </Card>
  );
}

/**
 * Running the two AI-specific scanners against one repo, from the list.
 *
 * The same call path the target page's scan buttons already use --
 * `api.runScan` dispatches, `useScanRun` follows the run from queued to
 * settled -- rather than a second route to POST /api/scans/run that would
 * word the same states differently. A scan started here is the same scan,
 * and shows up on the target page's own progress line via the shared
 * active-scan poll.
 *
 * Nothing here reports success the run has not earned: a dispatch the
 * server refused, and a dispatch whose outcome is still unknown, each
 * render as themselves rather than as a finished scan (AGENTS.md 1.4).
 */
function RepoScanActions({
  target,
  onScanCompleted,
  alreadyScanning,
  onDispatched,
}: {
  target: Target;
  onScanCompleted: () => void;
  /**
   * A scan is already running for this target according to the server, which
   * this component cannot know on its own: it only remembers runs it started
   * itself, so a scan dispatched from the target page, another tab, or this
   * page before a reload left the button enabled. The API does not dedupe, so
   * a second click really does start a second clone, a second tool run and a
   * second ingest, and spends another of the caller's rate-limit budget.
   */
  alreadyScanning: boolean;
  onDispatched: () => void;
}) {
  // `useScanRun` follows one run at a time, so this row reports one at a
  // time: the buttons stay disabled until the dispatched scan settles
  // rather than starting a second one this component could not then speak
  // for. `tool` is which scanner the state below belongs to.
  const [tool, setTool] = useState<AiTool | null>(null);
  const [dispatching, setDispatching] = useState(false);

  const scan = useScanRun({ onCompleted: onScanCompleted });

  const isActive = target.is_active !== false;
  const inFlight = dispatching || alreadyScanning || scan.phase === "queued" || scan.phase === "running";

  async function run(nextTool: AiTool) {
    setTool(nextTool);
    setDispatching(true);
    scan.reset();
    try {
      const res = await api.runScan(target.id, nextTool);
      if ("error" in res) {
        // A refused dispatch (deactivated target, tool not assigned to the
        // workspace, rate limit) never produces a scan id, so it settles
        // through the same failure path as a run that dies later on.
        scan.fail(res.error);
        return;
      }
      scan.track(res.scan_id);
      // Make the new run visible to the shared active-scans poll immediately,
      // so every other row and surface reading it stops offering a duplicate
      // before the next cadence tick.
      onDispatched();
    } catch (err) {
      scan.fail(getErrorMessage(err, "Scan could not be started"));
    } finally {
      setDispatching(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {AI_TOOLS.map((t) => (
        <Button
          key={t}
          size="sm"
          variant="outline"
          className="h-7 text-xs"
          // Deactivated targets refuse every scan server-side; disabled
          // rather than hidden, matching the AI Bill of Materials action
          // above and the target page's own buttons.
          disabled={!isActive || inFlight}
          title={isActive ? undefined : DEACTIVATED_TITLE}
          // Every row carries identically labelled buttons, so the
          // accessible name has to say which repo this one would scan.
          aria-label={`Run ${TOOL_LABEL[t]} on ${target.name}`}
          onClick={() => run(t)}
        >
          Run {TOOL_LABEL[t]}
        </Button>
      ))}

      {!isActive && <span className="text-xs text-muted-foreground">Reactivate this target to scan it.</span>}

      {dispatching && tool && (
        <span role="status" className="text-xs text-muted-foreground">
          Starting {TOOL_LABEL[tool]}...
        </span>
      )}

      {!dispatching && tool && scan.phase && (
        <>
          <ScanProgress
            phase={scan.phase}
            tool={TOOL_LABEL[tool]}
            elapsedSeconds={scan.elapsedSeconds}
            etaSeconds={scan.etaSeconds}
            error={scan.error}
          />
          {/* Renders only for a run the platform did not trust; a completed
              scan whose results are qualified must not read as a clean one. */}
          <ScanHealthBadge health={scan.health} />
        </>
      )}
    </div>
  );
}

// One badge per (AI-specific tool, repo). Three states, not two, per
// AGENTS.md #4 and the honesty rule this page was specifically asked to
// check: a positive count is unambiguous (the tool ran and found
// something), but "0" is not, by itself, a claim this codebase lets stand --
// it has to say whether it means "ran, clean" or "hasn't run".
function ToolBadge({
  tool,
  target,
  count,
  scanned,
  scanSummaryReady,
  findingsFailed,
}: {
  tool: AiTool;
  target: Target;
  count: number;
  scanned: boolean;
  scanSummaryReady: boolean;
  /** The findings query for this tool failed, so `count` is not a measurement. */
  findingsFailed: boolean;
}) {
  const label = TOOL_LABEL[tool];
  const href = `/findings?tool=${tool}&target_id=${target.id}&queue=all`;

  // A failed findings query leaves `count` at 0, which is not the same claim
  // as "scanned and clean" -- and the scan-history branches below would go on
  // to render "0 <tool>" or "<tool> not scanned" from it, both of which state
  // a measurement that was never taken. The aggregate cards at the top of
  // this page already treat their own query error this way; this is the same
  // rule applied per repo (AGENTS.md 1.4).
  if (findingsFailed) {
    return (
      <Link
        href={href}
        title={`${label} findings could not be loaded, so the count for this repo is not known.`}
        className="rounded border border-border px-2 py-1 text-muted-foreground hover:text-foreground hover:underline"
      >
        {label}: unknown
      </Link>
    );
  }

  if (count > 0) {
    return (
      <Link href={href} className="rounded border border-warning/30 bg-warning/10 px-2 py-1 text-warning hover:underline">
        {count} {label}
      </Link>
    );
  }

  // count === 0 and the scan-history fetch failed: cannot tell "clean" from
  // "never reached", so say neither. Still links through -- the findings
  // list underneath will genuinely show zero, matching this badge.
  if (!scanSummaryReady) {
    return (
      <Link
        href={href}
        title="Scan history is unavailable, so it is not known whether this tool has run against this repo."
        className="rounded border border-border px-2 py-1 text-muted-foreground hover:text-foreground hover:underline"
      >
        {label}: unknown
      </Link>
    );
  }

  if (!scanned) {
    return (
      <Link
        href={href}
        title={`${label} has not run against this repo yet.`}
        className="rounded border border-dashed border-border/70 px-2 py-1 text-muted-foreground/70 hover:text-foreground hover:underline"
      >
        {label} not scanned
      </Link>
    );
  }

  // count === 0 and scanned: a real, measured zero.
  return (
    <Link href={href} className="rounded border border-border px-2 py-1 text-muted-foreground hover:text-foreground hover:underline">
      0 {label}
    </Link>
  );
}
