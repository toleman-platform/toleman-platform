import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { api } from "@/lib/api";
import { CriticalityChip } from "@/components/criticality-chip";
import { FindingsList } from "@/components/findings-list";
import { ScanButtons } from "./scan-buttons";
import { TargetGroups } from "./target-groups";
import { PipelineIntegration } from "./pipeline-integration";
import { TargetEnforcement } from "./target-enforcement";
import { ApiScanConfig } from "./api-scan-config";
import { TargetTabs, normalizeTab } from "./target-tabs";
import { TargetOverview } from "./target-overview";
import { settleOrNull } from "@/lib/settle";
import { pageSizeFromParams } from "@/lib/pagination";

// Issue #197: the target detail page used to be one long scroll stacking
// posture, findings and five separate config sections. The settings alone
// span #61, #62, #66, #72 and #185, and were reachable from several
// different surfaces. Splitting them into sub-pages gives each concern its
// own URL, which is what makes a target linkable from a finding, a PR
// comment or a Slack alert -- see target-tabs.tsx for why tab state lives in
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

  const page = Math.max(1, Number(Array.isArray(sp.page) ? sp.page[0] : sp.page) || 1);
  const pageSize = pageSizeFromParams(sp.page_size);

  const [target, findingsResult, scanSummary, targetSummary] = await Promise.all([
    api.target(targetId),
    // Real pagination. This used to fetch page_size: 500 and hand the whole
    // lot to FindingsList with pageSize = findings.length, which meant the
    // pager rendered "Showing 1-500 of 1137" while the rows-per-page
    // selector said 25 -- and on a target with 1137 findings it shipped 500
    // rows to the browser in one response.
    api.findings({ target_id: targetId, page, page_size: pageSize }),
    // Degrades to {} rather than failing the page -- the overview then shows
    // "Never" for last scan, which is honest about not knowing.
    settleOrNull(api.scanSummary()).then((s) => s ?? {}),
    // Overview counts must cover the whole target, not the fetched page.
    settleOrNull(api.targetsSummary()).then((s) => s ?? {}),
  ]);
  const findings = findingsResult.items;
  const scanEntry = scanSummary[String(targetId)];

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
          <h1 className="text-2xl font-bold text-foreground">{target.name}</h1>
          <p className="mt-1 truncate text-sm text-muted-foreground">{target.repo_url}</p>
          <p className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
            <CriticalityChip label={target.label} />
            <span className="truncate">
              · risk weight {target.criticality_weight}/5 · branch {target.default_branch}
            </span>
          </p>
        </div>
        <ScanButtons targetId={targetId} />
      </div>

      <TargetTabs targetId={targetId} active={tab} vulnerabilityCount={findingsResult.total} />

      {tab === "overview" && (
        <TargetOverview target={target} summaryEntry={targetSummary[String(targetId)]} scanEntry={scanEntry} />
      )}

      {tab === "vulnerabilities" && (
        // Reuses the shared findings components rather than forking them, so
        // bulk triage, severity styling, SLA badges, enrichment and the
        // density behaviour from #172 all come along unchanged. The target
        // column is redundant here, hence passing only this target.
        <FindingsList
          findings={findings}
          total={findingsResult.total}
          page={page}
          pageSize={pageSize}
          targets={[target]}
        />
      )}

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
          </div>

          <div>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">Active API Scanning</h2>
            <ApiScanConfig targetId={targetId} initialApiBaseUrl={target.api_base_url} />
          </div>

          <PipelineIntegration
            targetId={targetId}
            initialIntegrated={target.pipeline_integrated}
            initialPrUrl={target.pipeline_pr_url}
          />
        </div>
      )}
    </div>
  );
}
