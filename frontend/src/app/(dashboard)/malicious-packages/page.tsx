"use client";

import Link from "next/link";
import { useState } from "react";
import { Bug, ExternalLink, RefreshCw, ShieldAlert } from "lucide-react";
import { api, Finding, Target } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { StatCard } from "@/components/ui/stat-card";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonList } from "@/components/ui/skeleton";
import { TargetPicker } from "@/components/target-picker";

// Issue #177/#181: malicious dependencies detected via OSV.dev. Hits are
// persisted as ordinary Critical `Finding` rows (tool="osv-malware"), so this
// page is a focused view over the findings the SBOM-generation pipeline
// already produces -- the same rows the Findings list shows, just filtered
// and re-assertable without regenerating an SBOM.

function severityVariant(severity: string): "destructive" | "warning" | "outline" {
  if (severity === "Critical") return "destructive";
  if (severity === "High") return "warning";
  return "outline";
}

export default function MaliciousPackagesPage() {
  const findingsQuery = useAsyncData<Finding[]>(() =>
    api.findings({ tool: "osv-malware", page_size: 500 }).then((r) => r.items),
  );
  const targetsQuery = useAsyncData<Target[]>(() => api.targets());
  const [checkState, setCheckState] = useState<Record<number, string>>({});
  const [chosenTargetId, setChosenTargetId] = useState<number | null>(null);

  const findings = findingsQuery.data ?? [];
  const targets = targetsQuery.data ?? [];
  const targetById = new Map(targets.map((t) => [t.id, t]));

  const affectedTargetIds = Array.from(new Set(findings.map((f) => f.target_id)));
  const openCount = findings.filter((f) => f.state === "Open").length;

  function malwareLabel(status: "clean" | "found" | "failed", count: number): string {
    if (status === "found") return `found ${count}`;
    if (status === "failed") return "check failed";
    return "clean";
  }

  async function recheck(targetId: number) {
    setCheckState((c) => ({ ...c, [targetId]: "checking" }));
    try {
      // Pull the latest GitHub dependency-graph inventory first (issue #226
      // follow-up) -- a manual scan that only re-checked whatever was
      // already persisted could still miss a package OSV just flagged if
      // that package was never in the last SBOM generation's Trivy scan to
      // begin with. import_github_sbom's own /github-sync endpoint already
      // runs the OSV malware check itself over the freshly-merged inventory
      // (best-effort), so one call covers both "import" and "check".
      //
      // Falls back to a plain re-check over whatever's already persisted
      // when the import can't run at all (no GitHub App/token configured
      // for this workspace, or the dependency graph is disabled/unavailable
      // -- a 502) -- the repo may still have a Trivy-sourced SBOM worth
      // re-checking even without GitHub access.
      let status: "clean" | "found" | "failed";
      let count: number;
      try {
        const res = await api.importGithubSbom(targetId);
        status = res.malware?.status ?? "clean";
        count = res.malware?.malicious_count ?? 0;
      } catch {
        const res = await api.malwareCheck(targetId);
        status = res.status;
        count = res.malicious_count;
      }
      setCheckState((c) => ({ ...c, [targetId]: malwareLabel(status, count) }));
      findingsQuery.refetch();
    } catch {
      setCheckState((c) => ({ ...c, [targetId]: "check failed" }));
    }
  }

  const loading = findingsQuery.isInitialLoading || targetsQuery.isInitialLoading;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Malicious Packages</h1>
        <p className="text-sm text-muted-foreground">
          Dependencies flagged as malicious (not merely vulnerable) by OSV.dev&apos;s OpenSSF dataset. Detected
          automatically during SBOM generation and re-checkable without regenerating an SBOM.
        </p>
      </div>

      {(findingsQuery.error || targetsQuery.error) && (
        <p className="text-sm text-destructive">
          {(findingsQuery.error ?? targetsQuery.error)?.message}
        </p>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          label="Malicious packages"
          value={findings.length}
          hint="Critical findings from tool osv-malware"
          icon={Bug}
          tone={findings.length > 0 ? "critical" : "default"}
          unknown={loading}
        />
        <StatCard
          label="Affected repos"
          value={affectedTargetIds.length}
          hint="repos with at least one malicious dependency"
          icon={ShieldAlert}
          tone={affectedTargetIds.length > 0 ? "attention" : "default"}
          unknown={loading}
        />
        <StatCard
          label="Open"
          value={openCount}
          hint="not yet triaged"
          icon={Bug}
          unknown={loading}
        />
      </div>

      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">Detected packages</h2>

        {loading && <SkeletonList count={4} />}

        {!loading && findings.length === 0 && (
          <EmptyState
            icon={Bug}
            title="No malicious packages detected"
            description="The OSV check runs automatically on each SBOM generation. Use Scan a repository below to pull the latest GitHub dependency inventory and re-check it against OSV's latest data on demand."
          />
        )}

        {!loading &&
          findings.map((f) => {
            const target = targetById.get(f.target_id);
            return (
              <Card key={f.id} className="border-border bg-card">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium text-foreground">{f.title}</span>
                      <Badge variant={severityVariant(f.severity)} className="shrink-0 text-[10px]">
                        {f.severity}
                      </Badge>
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

      {!loading && targets.length > 0 && (
        <div className="flex flex-col gap-3">
          <h2 className="text-sm font-medium text-foreground">Scan a repository</h2>
          <p className="text-xs text-muted-foreground">
            Pulls the latest dependency inventory from GitHub&apos;s dependency graph and runs the OSV check over it
            in one step. Falls back to checking whatever&apos;s already on file (from a prior{" "}
            <Link href="/sbom" className="text-accent-strong hover:underline">
              SBOM &amp; OSS Vulns
            </Link>{" "}
            generation) if GitHub import isn&apos;t available for this repo. Worth re-running on a repo already
            checked, too -- OSV adds malicious-package records continuously, so a package clean at scan time can be
            flagged later.
          </p>
          <Card className="border-border bg-card">
            <CardContent className="flex flex-wrap items-center gap-3 px-4 py-3">
              <TargetPicker
                targets={targets}
                value={chosenTargetId ?? targets[0]?.id ?? null}
                onChange={setChosenTargetId}
              />
              {(() => {
                const activeId = chosenTargetId ?? targets[0]?.id ?? null;
                const label = activeId !== null ? checkState[activeId] : undefined;
                return (
                  <>
                    {label && label !== "checking" && (
                      <span
                        className={
                          label === "clean"
                            ? "text-xs text-chart-5"
                            : label === "check failed"
                              ? "text-xs text-destructive"
                              : "text-xs text-warning"
                        }
                      >
                        {label}
                      </span>
                    )}
                    <Button
                      size="sm"
                      onClick={() => activeId !== null && recheck(activeId)}
                      disabled={activeId === null || label === "checking"}
                    >
                      <RefreshCw className={label === "checking" ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"} />
                      <span>{label === "checking" ? "Scanning..." : "Import & Check"}</span>
                    </Button>
                  </>
                );
              })()}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
