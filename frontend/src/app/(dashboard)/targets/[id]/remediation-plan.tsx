import Link from "next/link";
import { ChevronRight, PackageSearch } from "lucide-react";
import { findingRemediations } from "@/lib/api";
import type { PackageRemediation, RemediationCoverage, RemediationPlanResponse } from "@/types";
import { settledOr } from "@/std-lib";
import { cn } from "@/lib/utils";
import { SEVERITY_BORDER_COLOR } from "@/lib/severity";
import { DEFAULT_PAGE_SIZE } from "@/lib/pagination";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityChip } from "@/components/ui/severity-chip";
import { TruncateTooltip } from "@/components/ui/truncate-tooltip";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { ActivityPagination } from "@/components/ui/activity-pagination";
import { RemediationRaisePrButton } from "./remediation-raise-pr-button";
import { RemediationBulkRaise } from "./remediation-bulk-raise";
import { TargetAutoRaiseFixPrs } from "./target-auto-raise-fix-prs";

// Fix plans group CVEs by package upgrade. Render upgrade_to as the lowest version
// clearing the grouped CVEs, never latest/recommended. Always show unresolved CVEs on
// the same package; partial fixes must not read as fully fixed. Empty-plan claims
// require enrichment coverage. CVE links use the shared search parameter and queue=all
// so triage category exclusions cannot hide the findings.
function vulnerabilityLink(targetId: number, cveId: string): string {
  const params = new URLSearchParams({ tab: "vulnerabilities", queue: "all", search: cveId });
  return `/targets/${targetId}?${params.toString()}`;
}

/**
 * What this upgrade actually does to the package it names, stated as a
 * count rather than a verdict. The all-clear and the partial case are
 * deliberately different sentences -- "fixes all N" is the only shape
 * allowed to say nothing is left, precisely so silence on `unresolved`
 * below is never the only place that fact shows up.
 */
function summarize(plan: PackageRemediation): string {
  const total = plan.fixes_count + plan.unresolved.length;
  if (plan.unresolved.length === 0) {
    return `Fixes all ${plan.fixes_count} finding${plan.fixes_count === 1 ? "" : "s"} on this package.`;
  }
  return `Fixes ${plan.fixes_count} of ${total} findings on this package — ${plan.unresolved.length} left unresolved.`;
}

function FixRow({ targetId, cve_id, severity, title }: {
  targetId: number;
  cve_id: string;
  severity: PackageRemediation["highest_severity"];
  title?: string;
}) {
  return (
    <li>
      <Link
        href={vulnerabilityLink(targetId, cve_id)}
        className="flex items-center gap-2 rounded px-1 py-0.5 text-xs text-muted-foreground transition-colors hover:bg-accent/40 hover:text-foreground"
      >
        <SeverityChip severity={severity} size="sm" variant="dot" />
        <span className="text-code shrink-0">{cve_id}</span>
        {title !== undefined && <TruncateTooltip text={title} className="text-xs" />}
      </Link>
    </li>
  );
}

export function PackageRow({
  targetId,
  plan,
  targetName,
}: {
  targetId: number;
  plan: PackageRemediation;
  // Set only by the workspace-wide Fix Plan (Findings page): a package row
  // there can be about any target in the estate, so the card has to say
  // which one before the reader can act on it. The per-target Fix Plan tab
  // never passes this -- the target is already the whole page's context.
  targetName?: string;
}) {
  return (
    <Card className={cn("border-l-4 bg-card", SEVERITY_BORDER_COLOR[plan.highest_severity])}>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            {targetName && (
              <Link
                href={`/targets/${targetId}?tab=fix-plan`}
                className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground"
              >
                {targetName}
              </Link>
            )}
            <span className="font-semibold text-foreground">{plan.package}</span>
            <span className="text-muted-foreground">upgrade to</span>
            <span className="text-code font-medium text-foreground">{plan.upgrade_to}</span>
            {plan.ecosystem && (
              <Badge variant="outline" className="text-[10px] text-muted-foreground">
                {plan.ecosystem}
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <SeverityChip severity={plan.highest_severity} size="sm" />
            {/* (#247 follow-up) No AI here -- the fix plan already knows the
                exact target version, so this opens the PR directly rather
                than a diff-review dialog like the per-finding Suggest Fix
                flow. */}
            <RemediationRaisePrButton targetId={targetId} packageName={plan.package} />
          </div>
        </div>

        <p className="text-sm text-muted-foreground">{summarize(plan)}</p>

        {/* Collapsed by default: the sentence above already states the
            honest count ("fixes N of M"), so the per-CVE link list below it
            is drill-down detail, not the one place that count lives -- a
            package with a dozen findings on the same rule (a nodejs-debug
            ReDoS repeated across every file that pins it, say) was several
            screens tall before this. Native <details> so no client
            component is needed just to toggle visibility. */}
        <details className="group">
          <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-muted-foreground marker:content-none hover:text-foreground [&::-webkit-details-marker]:hidden">
            <ChevronRight className="h-3 w-3 shrink-0 transition-transform group-open:rotate-90" />
            {plan.fixes.length} finding{plan.fixes.length === 1 ? "" : "s"} fixed by this upgrade
          </summary>
          <ul className="mt-2 flex flex-col gap-0.5">
            {plan.fixes.map((fix) => (
              <FixRow
                key={fix.finding_id}
                targetId={targetId}
                cve_id={fix.cve_id}
                severity={fix.severity}
                title={fix.title}
              />
            ))}
          </ul>
        </details>

        {/* Deliberately unconditional whenever the array is non-empty: this
            block is the one place #247's whole reason for existing shows up
            on screen, so it is never collapsed behind a toggle or a "show
            unresolved" click the reader has to know to make. */}
        {plan.unresolved.length > 0 && (
          <div className="flex flex-col gap-1 rounded-md border border-warning/30 bg-warning/5 p-2">
            <p className="text-[11px] font-medium uppercase tracking-wide text-warning">
              Not fixed by this upgrade
            </p>
            <ul className="flex flex-col gap-0.5">
              {plan.unresolved.map((u) => (
                // No `title` from the backend for an unresolved CVE (see
                // RemediationUnresolved) -- shown as-is rather than
                // fabricating a label for it.
                <FixRow key={u.finding_id} targetId={targetId} cve_id={u.cve_id} severity={u.severity} />
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function findingsWord(count: number): string {
  return count === 1 ? "finding" : "findings";
}

/**
 * Choose empty-plan copy using enrichment coverage: no CVE-bearing findings; CVEs never
 * looked up; lookups without advisory records; or measured advisories with no fixed
 * version. Only the last establishes no known fix. State partial coverage explicitly.
 */
function emptyPlanCopy(coverage: RemediationCoverage | null): { title: string; description: string } {
  if (coverage === null) {
    return {
      title: "Fix coverage unknown",
      description:
        "Advisory coverage for this target is unknown, so this tab can't say whether upgrades exist for its open findings.",
    };
  }

  const { cve_findings, enriched_findings, findings_with_advisory } = coverage;

  if (cve_findings === 0) {
    return {
      title: "No CVE findings on this target",
      description:
        "The fix plan groups open findings that carry a CVE, and this target has none. SAST, secrets, IaC and licence findings can still be open — see Vulnerabilities.",
    };
  }

  // Three buckets, and they must add up to cve_findings: an advisory came
  // back, a lookup ran and found no record, or no lookup has run. Stating
  // only one of the last two leaves a reader subtracting and getting a
  // number no sentence on the page accounts for.
  const noRecord = Math.max(0, enriched_findings - findings_with_advisory);
  const unchecked = Math.max(0, cve_findings - enriched_findings);
  const remainderParts: string[] = [];
  if (noRecord > 0) {
    remainderParts.push(`${noRecord} returned no advisory record`);
  }
  if (unchecked > 0) {
    remainderParts.push(`${unchecked} ${unchecked === 1 ? "has" : "have"} not been looked up yet`);
  }
  const remainder = remainderParts.length > 0 ? ` Of the rest, ${remainderParts.join(", and ")}.` : "";

  if (enriched_findings === 0) {
    return {
      title: "No advisory data fetched yet",
      description: `None of this target's ${cve_findings} open CVE ${findingsWord(cve_findings)} has advisory data yet. Nothing has been checked, so no fix has been ruled out. Opening a finding in Vulnerabilities fetches its advisory.`,
    };
  }

  if (findings_with_advisory === 0) {
    return {
      title: "No advisory records found",
      description: `Lookups ran for ${enriched_findings} of ${cve_findings} open CVE ${findingsWord(cve_findings)} and returned no advisory record, so no fixed version is known — which is not the same as none existing.${
        unchecked > 0
          ? ` The other ${unchecked} ${unchecked === 1 ? "has" : "have"} not been looked up yet.`
          : ""
      }`,
    };
  }

  return {
    title: "No fixed versions published",
    description: `Advisories cover ${findings_with_advisory} of ${cve_findings} open CVE ${findingsWord(cve_findings)}, and none of them names a fixed version.${remainder} Those findings are still open — see Vulnerabilities.`,
  };
}

/**
 * Pure render of an already-settled fetch, split out from `RemediationPlan`
 * so the states below (failed / the four empty cases / populated) are
 * testable as plain component props rather than through a live fetch.
 */
export function RemediationPlanView({
  targetId,
  plans,
  coverage,
  failed,
  total,
  page = 1,
  pageSize = DEFAULT_PAGE_SIZE,
  autoRaiseEnabled = false,
}: {
  targetId: number;
  plans: PackageRemediation[];
  coverage: RemediationCoverage | null;
  failed: boolean;
  // Whole-target package count, not `plans.length` -- `plans` is one page
  // of it. Defaults to `plans.length` so a caller rendering the full,
  // unpaginated list (as every existing test here does) needs no change.
  total?: number;
  page?: number;
  pageSize?: number;
  autoRaiseEnabled?: boolean;
}) {
  const resolvedTotal = total ?? plans.length;

  if (failed) {
    return <ErrorState description="The fix plan couldn't be loaded from the API." action={<ReloadButton />} />;
  }

  if (resolvedTotal === 0) {
    const { title, description } = emptyPlanCopy(coverage);
    return (
      <EmptyState
        icon={PackageSearch}
        title={title}
        description={description}
        action={
          <Button asChild size="sm" variant="outline">
            <Link href={`/targets/${targetId}?tab=vulnerabilities`}>Go to Vulnerabilities</Link>
          </Button>
        }
      />
    );
  }

  // Real upgrades exist (resolvedTotal > 0) but this specific page has none
  // -- a stale/hand-edited `?page=` past the last one, most likely after
  // the plan shrank (a package got fixed elsewhere, a finding triaged
  // away). This is NOT the same fact as "no upgrades exist for this
  // target": rendering emptyPlanCopy here would claim things about
  // coverage/fixes that have nothing to do with why THIS page is blank.
  if (plans.length === 0) {
    // No pager here, deliberately: ActivityPagination's own range math
    // ("Showing X-Y of Z") assumes `page` is within range, and an
    // out-of-range `page` (that's the whole reason this branch exists)
    // would render a nonsensical range instead of a usable control. The
    // "Go to page 1" action below is the only navigation this state needs.
    return (
      <EmptyState
        icon={PackageSearch}
        title="No upgrades on this page"
        description={`Page ${page} is past the end of this target's ${resolvedTotal} upgrade${resolvedTotal === 1 ? "" : "s"}.`}
        action={
          <Button asChild size="sm" variant="outline">
            <Link href={`/targets/${targetId}?tab=fix-plan`}>Go to page 1</Link>
          </Button>
        }
      />
    );
  }

  // A populated plan can still be built on partial data: the upgrades shown
  // are real, and the CVEs nobody has looked up yet are neither fixed nor
  // fix-less, they are unmeasured. Saying so is the same rule the empty
  // state follows, applied to a list that would otherwise read as complete.
  // Keyed on `findings_with_advisory` -- an advisory actually came back --
  // not on `enriched_findings`, which only records that a lookup was
  // attempted. During an upstream outage every CVE is looked up and nothing
  // is found, so enriched_findings reaches cve_findings while the plan rests
  // on almost no data; keying on the attempt made the caveat disappear at
  // exactly the moment it was most needed.
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
    return `This plan is built on the ${findings_with_advisory} of ${cve_findings} open CVE ${findingsWord(cve_findings)} with an advisory.${rest}`;
  })();

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <p className="text-sm text-muted-foreground">
            {resolvedTotal} upgrade{resolvedTotal === 1 ? "" : "s"} would close open findings on this target.
          </p>
          {coverageNote && <p className="text-sm text-muted-foreground">{coverageNote}</p>}
          <TargetAutoRaiseFixPrs targetId={targetId} initialEnabled={autoRaiseEnabled} compact />
        </div>
        <RemediationBulkRaise targetId={targetId} totalPackages={resolvedTotal} />
      </div>
      <ActivityPagination total={resolvedTotal} page={page} pageSize={pageSize} position="top" />
      {/* Rendered in the order the backend returns: most findings closed
          first, ties broken by severity. Re-sorting here would be a second,
          possibly-drifting copy of that rule -- and this is exactly one
          page of that order, sliced server-side; never re-paginate `plans`
          itself, it is already the page the API returned. */}
      <div className="flex flex-col gap-3">
        {plans.map((plan) => (
          <PackageRow key={plan.package} targetId={targetId} plan={plan} />
        ))}
      </div>
      <ActivityPagination total={resolvedTotal} page={page} pageSize={pageSize} position="bottom" />
    </div>
  );
}

export async function RemediationPlan({
  targetId,
  page,
  pageSize,
  autoRaiseEnabled = false,
}: {
  targetId: number;
  page?: number;
  pageSize?: number;
  autoRaiseEnabled?: boolean;
}) {
  // `null` rather than an empty response: a failed fetch must not decay into
  // zero plans with zero coverage, which would render as the strongest
  // negative this tab can state ("no CVE findings on this target") for a
  // request that never arrived. `failed` keeps the two apart, and a null
  // coverage keeps them apart a second time if the value is ever read
  // without it.
  const [result, failed] = await settledOr<RemediationPlanResponse | null>(
    findingRemediations(targetId, page, pageSize),
    null,
  );
  return (
    <RemediationPlanView
      targetId={targetId}
      plans={result?.plans ?? []}
      coverage={result?.coverage ?? null}
      failed={failed}
      total={result?.total}
      page={page}
      pageSize={pageSize}
      autoRaiseEnabled={autoRaiseEnabled}
    />
  );
}
