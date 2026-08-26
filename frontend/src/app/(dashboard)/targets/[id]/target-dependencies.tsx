import { api, SbomComponent } from "@/lib/api";
import { settleOrNull } from "@/lib/settle";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { Package } from "lucide-react";

// (#227) Human label for a component's provenance source. Legacy rows from
// before trivy SBOM generation was removed keep a neutral label rather than
// being dropped or relabelled as a newer source.
function sourceLabel(source?: string): string {
  switch (source) {
    case "github":
      return "graph";
    case "upload":
      return "upload";
    case "github,upload":
      return "graph + upload";
    case "trivy":
      return "manifest";
    case "trivy,github":
      return "manifest + graph";
    default:
      return source ?? "manifest";
  }
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
export async function TargetDependencies({ targetId }: { targetId: number }) {
  const sbom = await settleOrNull(api.getSbom(targetId));

  // settleOrNull rather than letting this throw: a target whose SBOM has
  // never been generated is an ordinary state, not a page error.
  if (!sbom || sbom.components.length === 0) {
    return (
      <EmptyState
        icon={Package}
        title="No dependency inventory yet"
        description="Run an SBOM scan for this target from SBOM & OSS Vulns to populate it."
      />
    );
  }

  const components: SbomComponent[] = sbom.components;
  const newCount = components.filter((c) => c.is_new).length;

  return (
    <div className="flex flex-col gap-3">
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
