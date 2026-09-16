"use client";

import Link from "next/link";
import { useState } from "react";
import {
  Bug,
  ExternalLink,
  Package,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import { api, ApiError, type Finding, type Target } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspaceScopedSelection } from "@/hooks/use-workspace-scoped-selection";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonList } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/ui/page-header";
import { AlertBanner } from "@/components/ui/alert-banner";
import { SeverityChip } from "@/components/ui/severity-chip";
import { TargetPicker } from "@/components/features/targets";
import { timeAgo } from "@/lib/format/date";

// Issue #177/#181: malicious dependencies detected via OSV.dev. Hits are
// persisted as ordinary Critical `Finding` rows (tool="osv-malware"), so this
// page is a focused view over the findings the SBOM-generation pipeline
// already produces; the same rows the Findings list shows, just filtered
// and re-assertable without regenerating an SBOM.
//
// A target with nothing flagged used to render as three zeros and a
// sentence -- indistinguishable from a target nobody had ever checked. The
// per-repository list below (backed by Target.malware_last_checked_at /
// _last_check_status / _packages_checked, stamped by
// app.core.osv_malware_ingestion.check_and_ingest_malware on every
// completed check) is what turns "clean" into a claim with evidence behind
// it: how many packages, compared when, and a link to the exact inventory
// that was compared.

// OSV serves the malicious-packages dataset live from /v1/querybatch; there
// is no dataset export or version number to cite, so the honest "source"
// statement is what was queried and how current the answer is, not a
// pinned version this page cannot actually name.
const OSV_SOURCE_NOTE =
  "Source: OSV.dev's OpenSSF malicious-packages advisories, queried live against each target's SBOM inventory on every check. OSV does not publish a dataset version to pin to -- how recently a repo was checked is the freshness signal.";

export default function MaliciousPackagesPage() {
  const { activeWorkspaceId } = useWorkspaceContext();
  // (#519) Also scoped by workspace, same bug class the picker's own fix is
  // about: this predates the multi-select work, but an OSV finding from a
  // repo outside the active workspace has no business in this page's
  // headline stats or detected-package list either.
  const findingsQuery = useAsyncData<Finding[]>(
    () => api.findings({ tool: "osv-malware", page_size: 500, workspace_id: activeWorkspaceId }).then((r) => r.items),
    { deps: [activeWorkspaceId] },
  );
  // (#520) Workspace-scoped, same pattern as sbom/page.tsx.
  const targetsQuery = useAsyncData<Target[]>(() => api.targets({ workspace_id: activeWorkspaceId }), {
    deps: [activeWorkspaceId],
  });
  const [checkState, setCheckState] = useState<Record<number, string>>({});
  const [importWarning, setImportWarning] = useState<Record<number, string>>({});
  // (#519) Resets on a workspace switch -- this picker has no "All
  // repositories" pseudo-value, so any selection is workspace-specific.
  const [chosenTargetIds, setChosenTargetIds] = useWorkspaceScopedSelection(activeWorkspaceId);

  const targets = (targetsQuery.data ?? []).filter(
    (t) => activeWorkspaceId === null || t.workspace_id === activeWorkspaceId,
  );
  // `??`, not a length check: `chosenTargetIds` is `null` only when nothing
  // has been explicitly chosen yet -- an explicit Clear in the picker sets
  // it to `[]`, which must stay `[]` here rather than silently snapping
  // back to the default (#519 review).
  const targetIds = chosenTargetIds ?? (targets[0] ? [targets[0].id] : []);
  const targetById = new Map(targets.map((t) => [t.id, t]));
  // Filtered again client-side, same reasoning as `targets`: a workspace
  // switch's refetch keeps the previous workspace's findings on screen
  // while it's in flight.
  const targetIdSet = new Set(targets.map((t) => t.id));
  const findings = (findingsQuery.data ?? []).filter((f) => targetIdSet.has(f.target_id));

  const affectedTargetIds = Array.from(new Set(findings.map((f) => f.target_id)));
  const openCount = findings.filter((f) => f.state === "Open").length;

  // Per-target open-finding count, for the coverage list's status label.
  // Deliberately read off the same `findings` fetch the stat cards above
  // use (current triage truth), rather than off `malware_last_check_status`
  // (a snapshot of what OSV said *at check time*): a package flagged by the
  // last check and since triaged to Mitigated on the Findings page must not
  // keep reading "found" here just because nobody has re-run the check.
  const openCountByTarget = new Map<number, number>();
  for (const f of findings) {
    if (f.state === "Open") {
      openCountByTarget.set(f.target_id, (openCountByTarget.get(f.target_id) ?? 0) + 1);
    }
  }

  // Aggregate "how much has actually been verified" figure. Only counts
  // targets whose last check *completed* (Target.malware_packages_checked
  // is non-null); a target that has only ever failed a check contributes
  // nothing here, same reasoning as the per-row unknown state below.
  const checkedTargets = targets.filter((t) => t.malware_packages_checked !== null);
  const totalPackagesChecked = checkedTargets.reduce(
    (sum, t) => sum + (t.malware_packages_checked ?? 0),
    0,
  );
  // Unknown only when there is something to have checked and none of it
  // ever has been -- distinct from zero registered targets, which is a
  // real, measured "nothing to check" rather than an unmeasured gap.
  const packagesCheckedUnknown = targets.length > 0 && checkedTargets.length === 0;

  function malwareLabel(status: "clean" | "found" | "failed", count: number): string {
    if (status === "found") return `found ${count}`;
    if (status === "failed") return "check failed";
    return "clean";
  }

  // The dependency-graph API 403s when it's disabled for the repo, or 404s
  // when the repo/graph has never been built; both surface from the
  // backend as a 502 whose detail names the real HTTP status GitHub gave.
  // Matched on wording rather than a structured code because
  // DependencyGraphUnavailable's message is the only signal the API
  // forwards; this is deliberately specific so a transient/network failure
  // doesn't get mislabeled as "not enabled" when it isn't.
  function isDependencyGraphDisabled(err: unknown): boolean {
    return err instanceof ApiError && err.status === 502 && /403|disabled|404/.test(err.message);
  }

  async function recheck(targetId: number) {
    setCheckState((c) => ({ ...c, [targetId]: "checking" }));
    setImportWarning((w) => ({ ...w, [targetId]: "" }));
    try {
      // Pull the latest GitHub dependency-graph inventory first (issue #226
      // follow-up); a manual scan that only re-checked whatever was
      // already persisted could still miss a package OSV just flagged if
      // that package was never in the last SBOM generation's Trivy scan to
      // begin with. import_github_sbom's own /github-sync endpoint already
      // runs the OSV malware check itself over the freshly-merged inventory
      // (best-effort), so one call covers both "import" and "check".
      //
      // Falls back to a plain re-check over whatever's already persisted
      // when the import can't run at all (no GitHub App/token configured
      // for this workspace, or the dependency graph is disabled/unavailable;
      // a 502); the repo may still have a Trivy-sourced SBOM worth
      // re-checking even without GitHub access. The fallback is silent for
      // any *other* import failure (network blip, unexpected GitHub
      // response); only "the graph isn't enabled for this repo" is
      // specific and actionable enough to call out on its own.
      let status: "clean" | "found" | "failed";
      let count: number;
      try {
        const res = await api.importGithubSbom(targetId);
        status = res.malware?.status ?? "clean";
        count = res.malware?.malicious_count ?? 0;
      } catch (err) {
        if (isDependencyGraphDisabled(err)) {
          setImportWarning((w) => ({
            ...w,
            [targetId]: "GitHub dependency graph isn't enabled for this repo, checked existing inventory only.",
          }));
        }
        const res = await api.malwareCheck(targetId);
        status = res.status;
        count = res.malicious_count;
      }
      setCheckState((c) => ({ ...c, [targetId]: malwareLabel(status, count) }));
      // Both findings (the detected-package list) and targets (packages
      // checked / last-checked evidence, stamped server-side by this same
      // request) changed; refetching only one would leave the other half
      // of the page showing a check that just happened as if it hadn't.
      findingsQuery.refetch();
      targetsQuery.refetch();
    } catch {
      setCheckState((c) => ({ ...c, [targetId]: "check failed" }));
    }
  }

  const loading = findingsQuery.isInitialLoading || targetsQuery.isInitialLoading;
  // A query that has errored must not fall through to its "loaded, and
  // there's nothing here" empty state -- that reads as a verified clean
  // result when the truth is "we don't know, the request failed". The
  // critical banner below already says so; the sections beneath it render
  // only what actually loaded.
  const findingsUnavailable = !loading && !!findingsQuery.error;
  const targetsUnavailable = !loading && !!targetsQuery.error;

  // Coverage list order: repositories with something currently open first
  // (the most actionable rows), then repositories that have never
  // completed a check (a real gap, not a clean result), then everything
  // else alphabetically. A long, unsorted dump of mostly-clean repos would
  // bury the two rows that actually need a look.
  const sortedTargets = [...targets].sort((a, b) => {
    const openA = openCountByTarget.get(a.id) ?? 0;
    const openB = openCountByTarget.get(b.id) ?? 0;
    if (openA !== openB) return openB - openA;
    const neverA = a.malware_last_checked_at === null;
    const neverB = b.malware_last_checked_at === null;
    if (neverA !== neverB) return neverA ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Malicious Packages"
        description="Malicious dependencies detected in target dependency graphs via OSV.dev's OpenSSF dataset."
      />

      {(findingsQuery.error || targetsQuery.error) && (
        <AlertBanner tone="critical">
          {(findingsQuery.error ?? targetsQuery.error)?.message}
        </AlertBanner>
      )}

      <StatGrid columns={4}>
        <StatCard
          label="Malicious packages"
          value={findings.length}
          hint="Critical findings from tool osv-malware"
          icon={Bug}
          tone={findings.length > 0 ? "critical" : "default"}
          unknown={loading || findingsUnavailable}
          unknownHint={findingsUnavailable ? "Findings failed to load" : undefined}
        />
        <StatCard
          label="Affected repos"
          value={affectedTargetIds.length}
          hint="repos with at least one malicious dependency"
          icon={ShieldAlert}
          tone={affectedTargetIds.length > 0 ? "attention" : "default"}
          unknown={loading || findingsUnavailable}
          unknownHint={findingsUnavailable ? "Findings failed to load" : undefined}
        />
        <StatCard
          label="Open"
          value={openCount}
          hint="not yet triaged"
          icon={Bug}
          unknown={loading || findingsUnavailable}
          unknownHint={findingsUnavailable ? "Findings failed to load" : undefined}
        />
        <StatCard
          label="Packages checked"
          value={totalPackagesChecked}
          hint={
            targets.length > 0
              ? `across ${checkedTargets.length} of ${targets.length} repo${targets.length === 1 ? "" : "s"} checked`
              : "no repositories registered"
          }
          icon={Package}
          unknown={loading || targetsUnavailable || packagesCheckedUnknown}
          unknownHint={
            targetsUnavailable
              ? "Repositories failed to load"
              : packagesCheckedUnknown
                ? "No repository has completed an OSV check yet"
                : undefined
          }
        />
      </StatGrid>

      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">Detected packages</h2>

        {loading && <SkeletonList count={4} />}

        {!loading && findingsUnavailable && (
          <EmptyState
            icon={Bug}
            title="Detected packages unavailable"
            description="The findings list failed to load, so this cannot say whether any malicious packages are flagged. Reload to retry."
          />
        )}

        {!loading && !findingsUnavailable && findings.length === 0 && (
          <EmptyState
            icon={Bug}
            title="No malicious packages detected"
            description="The OSV check runs automatically on each SBOM generation. See Check coverage by repository below for what was actually compared and when; use Scan a repository to pull the latest GitHub dependency inventory and re-check it on demand."
          />
        )}

        {!loading &&
          !findingsUnavailable &&
          findings.map((f) => {
            const target = targetById.get(f.target_id);
            return (
              <Card key={f.id} className="border-border bg-card">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium text-foreground">{f.title}</span>
                      <SeverityChip severity={f.severity} size="sm" />
                    </div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-muted-foreground">
                      <span className="font-mono">{f.file_path}</span>
                      <span>·</span>
                      {target ? (
                        <Link href={`/targets/${target.id}`} className="hover:underline">
                          {target.name}
                        </Link>
                      ) : (
                        <span>target #{f.target_id}</span>
                      )}
                      {/* (#273) These findings outlive a deactivation by
                          design -- history is retained. Saying so stops a
                          reader assuming the repo is still being watched for
                          newly-published malicious packages, which it is
                          not: the OSV re-check refuses a deactivated
                          target. */}
                      {target?.is_active === false && (
                        <Badge variant="warning" className="shrink-0 text-[10px]">
                          Deactivated
                        </Badge>
                      )}
                      <span>·</span>
                      <span>{f.state}</span>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <a
                      href={`https://osv.dev/vulnerability/${f.rule_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-accent-strong hover:underline"
                    >
                      {f.rule_id}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                </CardContent>
              </Card>
            );
          })}
      </div>

      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">Check coverage by repository</h2>
        <p className="text-xs text-muted-foreground">{OSV_SOURCE_NOTE}</p>

        {loading && <SkeletonList count={4} />}

        {!loading && targetsUnavailable && (
          <EmptyState
            icon={Package}
            title="Coverage unavailable"
            description="The repository list failed to load, so per-repository check status cannot be shown. Reload to retry."
          />
        )}

        {!loading && !targetsUnavailable && targets.length === 0 && (
          <EmptyState
            icon={Package}
            title="No repositories registered"
            description="Register a repository as a target to start checking its dependencies against OSV."
          />
        )}

        {!loading &&
          !targetsUnavailable &&
          sortedTargets.map((t) => {
            const openForTarget = openCountByTarget.get(t.id) ?? 0;
            const neverChecked = t.malware_last_checked_at === null;
            return (
              <Card key={t.id} className="border-border bg-card">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link href={`/targets/${t.id}`} className="truncate font-medium text-foreground hover:underline">
                        {t.name}
                      </Link>
                      {neverChecked ? (
                        <Badge variant="outline" className="shrink-0 text-[10px] text-muted-foreground">
                          <ShieldQuestion className="h-3 w-3" />
                          Never checked
                        </Badge>
                      ) : openForTarget > 0 ? (
                        <Badge variant="destructive" className="shrink-0 text-[10px]">
                          <ShieldAlert className="h-3 w-3" />
                          {openForTarget} open
                        </Badge>
                      ) : (
                        <Badge variant="success" className="shrink-0 text-[10px]">
                          <ShieldCheck className="h-3 w-3" />
                          Clean
                        </Badge>
                      )}
                      {t.is_active === false && (
                        <Badge variant="warning" className="shrink-0 text-[10px]">
                          Deactivated
                        </Badge>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {t.malware_last_checked_at === null
                        ? "Never checked against OSV. Run Scan a repository below to establish a baseline."
                        : `Compared ${t.malware_packages_checked ?? 0} package${t.malware_packages_checked === 1 ? "" : "s"} against OSV's malicious-package advisories ${timeAgo(t.malware_last_checked_at)}.`}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Link
                      href={`/targets/${t.id}?tab=dependencies`}
                      className="flex items-center gap-1 text-xs text-accent-strong hover:underline"
                    >
                      View SBOM
                      <ExternalLink className="h-3 w-3" />
                    </Link>
                  </div>
                </CardContent>
              </Card>
            );
          })}
      </div>

      {!loading && !targetsUnavailable && targets.length > 0 && (
        <div className="flex flex-col gap-3">
          <h2 className="text-sm font-medium text-foreground">Scan a repository</h2>
          <p className="text-xs text-muted-foreground">
            Pulls the latest dependency inventory from GitHub&apos;s dependency graph and runs the OSV check over it
            in one step. Falls back to checking whatever&apos;s already on file (from a prior{" "}
            <Link href="/sbom" className="text-accent-strong hover:underline">
              SBOM &amp; OSS Vulns
            </Link>{" "}
            generation) if GitHub import isn&apos;t available for this repo. Worth re-running on a repo already
            checked, too; OSV adds malicious-package records continuously, so a package clean at scan time can be
            flagged later.
          </p>
          <Card className="border-border bg-card">
            <CardContent className="flex flex-col gap-2 px-4 py-3">
              <div className="flex flex-wrap items-center gap-3">
                <TargetPicker targets={targets} value={targetIds} onChange={setChosenTargetIds} />
                {(() => {
                  const activeIds = targetIds;
                  const checking = activeIds.some((id) => checkState[id] === "checking");
                  // (#273) Both endpoints this button calls (/github-sync
                  // and /malware-check) refuse a deactivated target, because
                  // both persist Critical findings and fan out to Jira/SIEM/
                  // notifications. The button has to say so rather than
                  // firing and reporting "check failed", which would read as
                  // an OSV outage -- the opposite of what actually happened.
                  const deactivatedIds = activeIds.filter((id) => targetById.get(id)?.is_active === false);
                  const allDeactivated = activeIds.length > 0 && deactivatedIds.length === activeIds.length;
                  // Only shown for a single-repo selection; with several repos
                  // selected each one's own row below still carries its own
                  // status label, and one shared line here can't speak for all
                  // of them at once.
                  const singleLabel = activeIds.length === 1 ? checkState[activeIds[0]] : undefined;
                  return (
                    <>
                      {deactivatedIds.length > 0 && (
                        <span className="text-xs text-warning">
                          {deactivatedIds.length === activeIds.length
                            ? "This repo is deactivated; scanning is off."
                            : `${deactivatedIds.length} of ${activeIds.length} selected repos are deactivated and will be skipped.`}
                        </span>
                      )}
                      {!allDeactivated && singleLabel && singleLabel !== "checking" && (
                        <span
                          className={
                            singleLabel === "clean"
                              ? "text-xs text-chart-5"
                              : singleLabel === "check failed"
                                ? "text-xs text-destructive"
                                : "text-xs text-warning"
                          }
                        >
                          {singleLabel}
                        </span>
                      )}
                      <Button
                        size="sm"
                        onClick={() =>
                          Promise.all(
                            activeIds
                              .filter((id) => targetById.get(id)?.is_active !== false)
                              .map((id) => recheck(id)),
                          )
                        }
                        disabled={activeIds.length === 0 || checking || allDeactivated}
                        title={
                          allDeactivated
                            ? "This target is deactivated; scanning is off. Reactivate it on the target page."
                            : undefined
                        }
                      >
                        <RefreshCw className={checking ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"} />
                        <span>
                          {checking
                            ? "Scanning..."
                            : activeIds.length > 1
                              ? `Import & Check ${activeIds.length} repos`
                              : "Import & Check"}
                        </span>
                      </Button>
                    </>
                  );
                })()}
              </div>
              {(() => {
                const activeIds = targetIds;
                if (activeIds.length !== 1) return null;
                const warning = importWarning[activeIds[0]];
                return warning ? <p className="text-xs text-warning">{warning}</p> : null;
              })()}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
