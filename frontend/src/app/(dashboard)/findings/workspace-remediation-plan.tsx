import Link from "next/link";
import { PackageSearch } from "lucide-react";
import { findingRemediationsWorkspace } from "@/lib/api";
import type { PackageRemediation, RemediationCoverage, RemediationPlanResponse } from "@/types";
import { settledOr } from "@/std-lib";
import { DEFAULT_PAGE_SIZE } from "@/lib/pagination";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { ActivityPagination } from "@/components/ui/activity-pagination";
import { PackageRow } from "../targets/[id]/remediation-plan";

// (#247 follow-up) The Fix Plan tab exists per-target, but a security
// engineer owns a whole estate, not one repo at a time -- "what closes the
// most open findings for the least work" is exactly as useful asked across
// every target as it is asked about one. This is that same question,
// answered by GET /api/findings/remediations/workspace
// (backend/app/core/remediation.py's workspace_remediation_plan), which
// fans the identical per-target grouping out across targets rather than
// merging packages across them: "starlette" needing an upgrade on two
// different repos is two rows here, each tagged with which target it's
// for -- a fix is only ever actionable against one specific repo.
//
// Deliberately NOT exposing "Raise all" or the auto-raise toggle here:
// those are per-target actions (the per-target tab keeps them), and a
// button that raises PRs across every repository in the workspace at once
// is a much bigger, riskier action than this view's job of triage and
// visibility.

function findingsWord(count: number): string {
  return count === 1 ? "finding" : "findings";
}

/**
 * Same four-state shape as the per-target tab's emptyPlanCopy (see that
 * file's docstring for why the branches exist and in what order), reworded
 * for "across your targets" rather than "on this target" -- kept as its
 * own copy rather than a parameterized shared function so each surface's
 * wording can be edited independently without threading string fragments
 * through a shared contract.
 */
function emptyWorkspacePlanCopy(coverage: RemediationCoverage | null): { title: string; description: string } {
  if (coverage === null) {
    return {
      title: "Fix coverage unknown",
      description:
        "Advisory coverage across your targets is unknown, so this view can't say whether upgrades exist for their open findings.",
    };
  }

  const { cve_findings, enriched_findings, findings_with_advisory } = coverage;

  if (cve_findings === 0) {
    return {
      title: "No CVE findings across your targets",
      description:
        "The fix plan groups open findings that carry a CVE, and none of your targets have any. SAST, secrets, IaC and licence findings can still be open — see Findings.",
    };
  }

  const noRecord = Math.max(0, enriched_findings - findings_with_advisory);
  const unchecked = Math.max(0, cve_findings - enriched_findings);
  const remainderParts: string[] = [];
  if (noRecord > 0) remainderParts.push(`${noRecord} returned no advisory record`);
  if (unchecked > 0) remainderParts.push(`${unchecked} ${unchecked === 1 ? "has" : "have"} not been looked up yet`);
  const remainder = remainderParts.length > 0 ? ` Of the rest, ${remainderParts.join(", and ")}.` : "";

  if (enriched_findings === 0) {
    return {
      title: "No advisory data fetched yet",
      description: `None of the ${cve_findings} open CVE ${findingsWord(cve_findings)} across your targets has advisory data yet. Nothing has been checked, so no fix has been ruled out.`,
    };
  }

  if (findings_with_advisory === 0) {
    return {
      title: "No advisory records found",
      description: `Lookups ran for ${enriched_findings} of ${cve_findings} open CVE ${findingsWord(cve_findings)} across your targets and returned no advisory record, so no fixed version is known — which is not the same as none existing.${
        unchecked > 0 ? ` The other ${unchecked} ${unchecked === 1 ? "has" : "have"} not been looked up yet.` : ""
      }`,
    };
  }

  return {
    title: "No fixed versions published",
    description: `Advisories cover ${findings_with_advisory} of ${cve_findings} open CVE ${findingsWord(cve_findings)} across your targets, and none of them names a fixed version.${remainder} Those findings are still open — see Findings.`,
  };
}

export function WorkspaceRemediationPlanView({
  plans,
  coverage,
  failed,
  total,
  page = 1,
  pageSize = DEFAULT_PAGE_SIZE,
}: {
  plans: PackageRemediation[];
  coverage: RemediationCoverage | null;
  failed: boolean;
  total?: number;
  page?: number;
  pageSize?: number;
}) {
  const resolvedTotal = total ?? plans.length;

  if (failed) {
    return <ErrorState description="The fix plan couldn't be loaded from the API." action={<ReloadButton />} />;
  }

  if (resolvedTotal === 0) {
    const { title, description } = emptyWorkspacePlanCopy(coverage);
    return (
      <EmptyState
        icon={PackageSearch}
        title={title}
        description={description}
        action={
          <Button asChild size="sm" variant="outline">
            <Link href="/targets">Browse targets</Link>
          </Button>
        }
      />
    );
  }

  // Same out-of-range-page state the per-target tab handles, and for the
  // same reason: a stale/hand-edited `?page=` past the last one is not the
  // same fact as "no upgrades exist", and ActivityPagination's own range
  // math assumes `page` is in range -- which this state specifically isn't.
  if (plans.length === 0) {
    return (
      <EmptyState
        icon={PackageSearch}
        title="No upgrades on this page"
        description={`Page ${page} is past the end of these ${resolvedTotal} upgrade${resolvedTotal === 1 ? "" : "s"}.`}
        action={
          <Button asChild size="sm" variant="outline">
            <Link href="/findings?tab=fix-plan">Go to page 1</Link>
          </Button>
        }
      />
    );
  }

  const coverageNote = (() => {
    if (coverage === null) return null;
    const { cve_findings, enriched_findings, findings_with_advisory } = coverage;
    if (findings_with_advisory >= cve_findings) return null;
    const noRecord = Math.max(0, enriched_findings - findings_with_advisory);
    const unchecked = Math.max(0, cve_findings - enriched_findings);
    const parts: string[] = [];
    if (noRecord > 0) parts.push(`${noRecord} returned no advisory record`);
    if (unchecked > 0) parts.push(`${unchecked} ${unchecked === 1 ? "has" : "have"} not been looked up yet`);
    const rest = parts.length > 0 ? ` Of the rest, ${parts.join(", and ")}.` : "";
    return `This plan is built on the ${findings_with_advisory} of ${cve_findings} open CVE ${findingsWord(cve_findings)} with an advisory, across your targets.${rest}`;
  })();

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        {resolvedTotal} upgrade{resolvedTotal === 1 ? "" : "s"} would close open findings across your targets.
      </p>
      {coverageNote && <p className="text-sm text-muted-foreground">{coverageNote}</p>}
      <ActivityPagination total={resolvedTotal} page={page} pageSize={pageSize} position="top" />
      {/* Same backend order as the per-target tab (most findings closed
          first, ties broken by severity then package then target name),
          already paginated server-side -- never re-sort or re-slice here. */}
      <div className="flex flex-col gap-3">
        {plans.map((plan) => (
          <PackageRow
            key={`${plan.target_id}-${plan.package}`}
            targetId={plan.target_id!}
            plan={plan}
            targetName={plan.target_name}
          />
        ))}
      </div>
      <ActivityPagination total={resolvedTotal} page={page} pageSize={pageSize} position="bottom" />
    </div>
  );
}

export async function WorkspaceRemediationPlan({
  workspaceId,
  page,
  pageSize,
}: {
  workspaceId?: number;
  page?: number;
  pageSize?: number;
}) {
  const [result, failed] = await settledOr<RemediationPlanResponse | null>(
    findingRemediationsWorkspace(workspaceId, page, pageSize),
    null,
  );
  return (
    <WorkspaceRemediationPlanView
      plans={result?.plans ?? []}
      coverage={result?.coverage ?? null}
      failed={failed}
      total={result?.total}
      page={page}
      pageSize={pageSize}
    />
  );
}
