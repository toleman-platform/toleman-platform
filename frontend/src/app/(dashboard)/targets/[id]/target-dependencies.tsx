import { api, SbomComponent, Target } from "@/lib/api";
import { settleOrNull } from "@/lib/settle";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { Package } from "lucide-react";
import { cn } from "@/lib/utils";

// (#330) Outcome of the automatic Dependency Graph import that runs when a
// target is created. Shown above the table, and above the empty state in
// particular: an empty inventory because GitHub refused to answer looks
// exactly like an empty inventory because the repo has no dependencies, and
// only one of those is good news. A null status is a target that predates
// the automatic import, so there is nothing to report and nothing is shown.
function DependencySyncNudge({ target }: { target: Target }) {
  const status = target.dependency_sync_status;
  if (!status) return null;

  const text: Record<string, string> = {
    pending: "Importing dependencies from GitHub...",
    ok: `${target.dependency_component_count ?? 0} component${target.dependency_component_count === 1 ? "" : "s"} imported from the GitHub dependency graph`,
    unavailable: "GitHub could not provide a dependency graph for this repo. The inventory below may be incomplete; a private repo needs the graph enabled and a token with access.",
    failed: "The automatic dependency import failed. Import from GitHub on the SBOM page to retry.",
  };
  const tone: Record<string, string> = {
    pending: "border-border text-muted-foreground",
    ok: "border-chart-5/40 text-chart-5",
    unavailable: "border-warning/40 text-warning",
    failed: "border-destructive/40 text-destructive",
  };

  return (
    <div className="flex items-start gap-2">
      <Badge variant="outline" className={cn("shrink-0 text-[10px] uppercase", tone[status])}>
        {status}
      </Badge>
      <p className="text-sm text-muted-foreground">
        {text[status]}
        {target.dependency_sync_error && status !== "pending" && (
          <span className="ml-1 font-mono text-xs">({target.dependency_sync_error})</span>
        )}
      </p>
    </div>
  );
}

// (#227) Human label for a component's provenance source. Legacy rows from
// before trivy SBOM generation was removed keep a neutral label rather than
// being dropped or relabelled as a newer source.
const SOURCE_LABELS: Record<string, string> = {
  github: "graph",
  upload: "upload",
  // Legacy, no longer produced: rows written while trivy generated the SBOM.
  trivy: "manifest",
};

// Labelled per part rather than per whole string. source is a merged set
// (_merge_sources in app/core/sbom_ingestion.py), and its order follows
// _SOURCE_ORDER with anything unrecognised appended, so a legacy "trivy" row
// re-seen by the Dependency Graph import merges to "github,trivy", not
// "trivy,github". Enumerating whole combinations missed that one and rendered
// the raw internal string in the table.
function sourceLabel(source?: string): string {
  if (!source) return "manifest";
  return source
    .split(",")
    .map((part) => SOURCE_LABELS[part] ?? part)
    .join(" + ");
}

// (#276) A per-target dependency inventory, separate from the findings list.
//
// The gap this closes: a target's page could only ever answer "what is
// currently flagged here", never "what is actually installed here". A clean
// repo with zero findings had nothing to show on this axis at all; which
// is exactly the repo where someone most wants to confirm the inventory was
// actually read, rather than assume silence means it was.
//
// Reads GET /api/sbom/{target_id}, which already returns exactly this
// (persisted SbomComponent rows for the default branch); no new backend
// was needed, only a per-target surface for data the global SBOM page was
// already showing across every target at once.
export async function TargetDependencies({ targetId, target }: { targetId: number; target: Target }) {
  const sbom = await settleOrNull(api.getSbom(targetId));

  // settleOrNull rather than letting this throw: a target whose SBOM has
  // never been generated is an ordinary state, not a page error.
  if (!sbom || sbom.components.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <DependencySyncNudge target={target} />
        <EmptyState
          icon={Package}
          title="No dependency inventory yet"
          description="Run an SBOM scan for this target from SBOM & OSS Vulns to populate it."
        />
      </div>
    );
  }

  const components: SbomComponent[] = sbom.components;
  const newCount = components.filter((c) => c.is_new).length;

  return (
    <div className="flex flex-col gap-3">
      <DependencySyncNudge target={target} />
      <p className="text-sm text-muted-foreground">
        {sbom.count} package{sbom.count === 1 ? "" : "s"} resolved for this target
        {newCount > 0 && <> · {newCount} first seen in the latest scan</>}
      </p>

      <Card className="border-border bg-card">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Package</th>
                  <th className="px-4 py-2 font-medium">Version</th>
                  <th className="px-4 py-2 font-medium">Type</th>
                  <th className="px-4 py-2 font-medium">Source</th>
                </tr>
              </thead>
              <tbody>
                {components.map((c) => (
                  <tr key={c.id} className="border-b border-border/50 last:border-0">
                    <td className="px-4 py-2">
                      <span className="text-foreground">{c.name}</span>
                      {c.is_new && (
                        <Badge variant="outline" className="ml-2 border-accent-strong/40 text-[10px] text-accent-strong">
                          new
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{c.version}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{c.package_type}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {sourceLabel(c.source)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
