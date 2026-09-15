import Link from "next/link";
import { ChevronLeft, PowerOff } from "lucide-react";
import { api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { CriticalityChip } from "@/components/features/targets";
import { FindingsFilterBar, FindingsGroupsList, FindingsList } from "@/components/features/findings";
import { FindingsCategoryTabs, type CategoryTab } from "@/components/findings-category-tabs";
import { ScanButtons } from "./scan-buttons";
import { TargetGroups } from "./target-groups";
import { PipelineIntegration } from "./pipeline-integration";
import { TargetEnforcement } from "./target-enforcement";
import { TargetDiffScope } from "./target-diff-scope";
import { TargetCloneCredentials } from "./target-clone-credentials";
import { TargetIdBadge } from "./target-id-badge";
import { ApiScanConfig } from "./api-scan-config";
import { ApiScanCredential } from "./api-scan-credential";
import { TargetLifecycle } from "./target-lifecycle";
import { TargetScanSchedule } from "./target-scan-schedule";
import { TargetTabs, normalizeTab } from "./target-tabs";
import { TargetOverview } from "./target-overview";
import { TargetDependencies } from "./target-dependencies";
import { TargetHistory } from "./target-history";
import { RemediationPlan } from "./remediation-plan";
// Both settle helpers, deliberately: `settleOrNull` where `null` is a usable
// sentinel on its own (the list and group fetches, each of which renders an
// ErrorState when it is null), and `settledOr` where the fallback is an empty
// collection that would otherwise be indistinguishable from a real result.
// See std-lib/async.ts for why that distinction is load-bearing here.
import { settledOr, settleOrNull } from "@/std-lib";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { QUEUES, parseFindingsView, queueFilters } from "@/lib/findings-view";

// Issue #197: the target detail page used to be one long scroll stacking
// posture, findings and five separate config sections. The settings alone
// span #61, #62, #66, #72 and #185, and were reachable from several
// different surfaces. Splitting them into sub-pages gives each concern its
// own URL, which is what makes a target linkable from a finding, a PR
// comment or a Slack alert; see target-tabs.tsx for why tab state lives in
// the query string rather than in component state.
export default async function TargetDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { id } = await params;
  const sp = await searchParams;
  const targetId = Number(id);
  const tab = normalizeTab(sp.tab);

  // The same queue/sort/filter vocabulary /findings uses, read from the same
  // parser (lib/findings-view.ts) so "Needs action" cannot come to mean one
  // thing on that page and something slightly different on this tab.
  const view = parseFindingsView(sp);
  const { severity, tool, fixability, state, search, page, pageSize, pageSizeRaw, queue, queued, grouped, sort, sortRaw, new_since_days, newSinceRaw } = view;

  // This tab is always one target, so target_id is pinned here rather than
  // read off the URL; everything else is the reader's.
  const findingFilters = {
    target_id: targetId,
    severity,
    tool,
    fixability,
    state,
    search,
    new_since_days,
    category: queued.category,
    exclude_category: queued.exclude_category,
    resolved: queued.resolved,
  };

  const [
    target,
    findingsResult,
    groupsResult,
    scanSettled,
    targetSettled,
    queueCounts,
    findingFacets,
  ] = await Promise.all([
    api.target(targetId),
    // Real pagination. This used to fetch page_size: 500 and hand the whole
    // lot to FindingsList with pageSize = findings.length, which meant the
    // pager rendered "Showing 1-500 of 1137" while the rows-per-page
    // selector said 25; and on a target with 1137 findings it shipped 500
    // rows to the browser in one response.
    grouped
      ? Promise.resolve(null)
      : settleOrNull(
          api.findings({
            ...findingFilters,
            sort: sort === "blast_radius" ? "exploitability" : sort,
            page,
            page_size: pageSize,
          }),
        ),
    grouped
      ? settleOrNull(api.findingGroups({ ...findingFilters, sort, page, page_size: pageSize }))
      : Promise.resolve(null),
    // Both summaries still degrade to {} rather than failing the page, but
    // `settledOr` keeps the *reason* the map is empty. These two used to be
    // `settleOrNull(...).then((s) => s ?? {})`, which threw the failure away
    // one line after producing it — and the overview then combined a
    // succeeding scan summary with a failing target summary into a green `0`
    // under the words "scanned, nothing open", on a repository that may have
    // hundreds of open findings. See target-overview.tsx for what each
    // boolean now suppresses.
    settledOr(api.scanSummary(), {}),
    // Overview counts must cover the whole target, not the fetched page.
    settledOr(api.targetsSummary(), {}),
    // One count per queue, under the filters that are active now, so each tab
    // count describes what clicking it would actually show.
    Promise.all(
      QUEUES.map((q) => {
        const qf = queueFilters(q.id);
        return api
          .findings({
            target_id: targetId,
            severity,
            tool,
            fixability,
            search,
            new_since_days,
            category: qf.category,
            exclude_category: qf.exclude_category,
            resolved: qf.resolved,
            page_size: 1,
          })
          .then((r): number | null => r.total)
          // `null`, not `0` — the same call #460 corrected on /findings, and
          // these counts feed the same component. All four are independent
          // requests, so when the findings API is down they fail together and
          // the tab strip would read "Needs action 0 / Licence review 0 /
          // Resolved 0 / All findings 0" directly above this tab's own
          // "couldn't be loaded" error box. Zero is a measurement; a failed
          // request has not made one. See CategoryTab.count.
          .catch(() => null);
      }),
    ),
    // Null on failure: FindingsFilterBar already renders its hardcoded
    // dimensions (severity, fixability, state) without facets, and a tab that
    // loses its tool filter is better than a tab that fails to render.
    api.findingFacets({ target_id: targetId, ...queued }).catch(() => null),
  ]);
  const [scanSummary, scanSummaryFailed] = scanSettled;
  const [targetSummary, targetSummaryFailed] = targetSettled;
  const findings = findingsResult?.items ?? [];
  const scanEntry = scanSummary[String(targetId)];

  function findingsHref(overrides: Record<string, string | undefined>): string {
    const params = new URLSearchParams();
    params.set("tab", "vulnerabilities");
    severity.forEach((v) => params.append("severity", v));
    tool.forEach((v) => params.append("tool", v));
    fixability.forEach((v) => params.append("fixability", v));
    state.forEach((v) => params.append("state", v));
    if (search) params.set("search", search);
    if (pageSizeRaw) params.set("page_size", pageSizeRaw);
    if (newSinceRaw) params.set("new_since_days", newSinceRaw);
    if (sortRaw) params.set("sort", sortRaw);
    if (queue !== "action") params.set("queue", queue);
    if (!grouped) params.set("view", "flat");
    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined) params.delete(key);
      else params.set(key, value);
    }
    // Changing queue rarely leaves the reader on a page that still exists.
    params.delete("page");
    return `/targets/${targetId}?${params.toString()}`;
  }

  // The tab badge used to read the flat list's `total`, which is null in the
  // grouped view. Taken from the "All findings" queue count instead, so the
  // number is the same whichever view the reader is in.
  //
  // `undefined` when that count failed, which makes TargetTabs omit the badge
  // rather than render "Vulnerabilities (0)" for a target whose findings were
  // never counted.
  const openFindingsCount = queueCounts[QUEUES.findIndex((q) => q.id === "all")] ?? undefined;

  const queueTabs: CategoryTab[] = QUEUES.map((q, i) => ({
    id: q.id,
    label: q.label,
    count: queueCounts[i] ?? null,
    href: findingsHref({ queue: q.id === "action" ? undefined : q.id, state: undefined }),
  }));

  return (
    <div className="flex flex-col gap-6">
      {/* Identity gets the full width; scan actions sit on their own row
          below. #186 and #189 took this from 5 tools to 7, and sharing a row
          with them truncated the repo URL and the branch line even at
          1440px. A header should say what this is, not compete with the
          actions you can take on it. */}
      <div className="flex flex-col gap-3">
        {/* A detail page reached from a list needs a way back to that list.
            The sidebar's Targets link goes to an unfiltered page 1, losing
            whatever search/sort/page the reader came from; this is the
            standard back affordance they expect and it costs one row. */}
        <Link
          href="/targets"
          className="flex w-fit items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          All targets
        </Link>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-bold text-foreground">{target.name}</h1>
            {/* (#273) A deactivated target has to *look* deactivated. The
                scan buttons below still render (the server refuses them
                anyway, and hiding them would leave someone wondering where
                they went), so the state has to be stated here or the page
                looks identical to an active target that simply isn't
                scanning right now. */}
            {target.is_active === false && (
              <Badge variant="warning" className="gap-1">
                <PowerOff className="h-3 w-3" />
                Deactivated
              </Badge>
            )}
          </div>
          <p className="mt-1 truncate text-sm text-muted-foreground">{target.repo_url}</p>
          <p className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <CriticalityChip label={target.label} />
            <span className="truncate">
              {/* "criticality weight", not "risk": see target-overview.tsx's
                  matching StatCard hint for why this can't share the word a
                  finding's own Risk score uses. */}
              · criticality weight {target.criticality_weight}/5 · branch {target.default_branch}
            </span>
            <TargetIdBadge targetId={targetId} />
          </p>
        </div>
        {target.is_active === false && (
          <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-xs text-muted-foreground">
            Scanning is off for this target. On-demand scans, CI pushes, PR Guardrail, active API scanning and
            the nightly baseline refresh are all refused. Existing findings and history are kept.{" "}
            <Link href={`/targets/${targetId}?tab=settings`} className="text-accent-strong underline underline-offset-2">
              Reactivate in Settings
            </Link>
            .
          </div>
        )}
        <ScanButtons targetId={targetId} workspaceId={target.workspace_id} isActive={target.is_active !== false} />
      </div>

      <TargetTabs targetId={targetId} active={tab} vulnerabilityCount={openFindingsCount} />

      {tab === "overview" && (
        <TargetOverview
          target={target}
          summaryEntry={targetSummary[String(targetId)]}
          scanEntry={scanEntry}
          summaryFailed={targetSummaryFailed}
          scanSummaryFailed={scanSummaryFailed}
        />
      )}

      {tab === "fix-plan" && <RemediationPlan targetId={targetId} />}

      {tab === "vulnerabilities" && (
        // Reuses the shared findings components rather than forking them, so
        // grouping, bulk triage, severity styling, SLA badges, enrichment and
        // the density behaviour from #172 all come along unchanged. The target
        // column is redundant here, hence passing only this target.
        //
        // This tab used to be a bare paginated list: no filters, no grouping,
        // no sort. On a target with 1,137 findings that is a 46-page scroll
        // with no way to narrow it -- the same thing that made /findings
        // unusable before it was grouped.
        <div className="flex flex-col gap-4">
          <FindingsCategoryTabs tabs={queueTabs} active={queue} />
          <FindingsFilterBar
            targets={[target]}
            groups={[]}
            // Scoped to this target, so every option the bar offers is one
            // that actually narrows this tab rather than the whole estate.
            facets={findingFacets}
            fallbackOptions={null}
            resolved={queued.resolved}
            grouped={grouped}
            sort={!grouped && sort === "blast_radius" ? "exploitability" : sort}
          />
          {grouped && groupsResult === null && (
            <ErrorState description="The findings list couldn't be loaded from the API." action={<ReloadButton />} />
          )}
          {grouped && groupsResult && (
            <FindingsGroupsList
              groups={groupsResult.items}
              total={groupsResult.total}
              totalFindings={groupsResult.total_findings}
              truncated={groupsResult.truncated}
              page={page}
              pageSize={pageSize}
              memberQuery={findingFilters}
              targets={[target]}
            />
          )}
          {!grouped && findingsResult === null && (
            <ErrorState description="The findings list couldn't be loaded from the API." action={<ReloadButton />} />
          )}
          {!grouped && findingsResult && (
            <FindingsList
              findings={findings}
              total={findingsResult.total}
              page={page}
              pageSize={pageSize}
              targets={[target]}
            />
          )}
        </div>
      )}

      {tab === "dependencies" && <TargetDependencies targetId={targetId} target={target} />}

      {tab === "history" && <TargetHistory targetId={targetId} />}

      {tab === "settings" && (
        <div className="flex flex-col gap-8">
          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">Groups</h2>
            <TargetGroups targetId={targetId} workspaceId={target.workspace_id} />
          </div>

          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">PR Guardrail</h2>
            <TargetEnforcement
              targetId={targetId}
              initialMode={target.enforcement_mode}
              initialEffectiveMode={target.effective_enforcement_mode ?? "block"}
              initialSource={target.enforcement_mode_source ?? "default"}
            />
            <div className="mt-3">
              <TargetDiffScope
                targetId={targetId}
                initialEnabled={target.diff_scoped_pr_scans ?? false}
              />
            </div>
          </div>

          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">Clone access</h2>
            <TargetCloneCredentials
              targetId={targetId}
              initialCertSet={target.client_cert_set ?? false}
              initialKeySet={target.client_key_set ?? false}
              initialProxyUrl={target.clone_proxy_url ?? ""}
            />
          </div>

          {/* (#306) Directly above Active API Scanning on purpose: the
              api_scan schedule's "no API base URL is set, so nothing will be
              probed" warning points at the field in the very next section,
              so the fix is right there rather than something to go hunting
              for. */}
          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">Scheduled scans</h2>
            <TargetScanSchedule targetId={targetId} />
          </div>

          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">Active API Scanning</h2>
            <ApiScanConfig targetId={targetId} initialApiBaseUrl={target.api_base_url} />
            <ApiScanCredential targetId={targetId} />
          </div>

          <PipelineIntegration
            targetId={targetId}
            initialIntegrated={target.pipeline_integrated}
            initialPrUrl={target.pipeline_pr_url}
          />

          {/* (#273) Last, and visually separated: deactivate is reversible
              config, delete is not something to put next to the group
              picker. */}
          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">Lifecycle</h2>
            <TargetLifecycle
              targetId={targetId}
              targetName={target.name}
              initialIsActive={target.is_active ?? true}
            />
          </div>
        </div>
      )}
    </div>
  );
}
