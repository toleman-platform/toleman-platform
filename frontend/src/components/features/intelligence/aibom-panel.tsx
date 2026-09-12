"use client";

import { Boxes, Database } from "lucide-react";
import { AiBomComponent, AiBomView, api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AsyncContent } from "@/components/ui/async-content";
import { ListRow, ListRows } from "@/components/ui/list-row";
import { useAsyncData } from "@/hooks/use-async-data";

// Issue #190: models and datasets a target depends on; the part a package
// SBOM is blind to. Reads persisted rows populated during SBOM generation, so
// this reflects the last run without re-scanning, same as the Components tab.
//
// Migrated to the #210 pattern layer: useAsyncData replaced a hand-rolled
// useEffect + loading/error/cancelled triple, and AsyncContent replaced the
// branch ladder. The panel gained a live region, aria-busy and a working
// retry it never had, without any of that being written here.
function ComponentRow({ component }: { component: AiBomComponent }) {
  const isModel = component.component_type === "machine-learning-model";
  const Icon = isModel ? Boxes : Database;
  return (
    <ListRow>
      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate font-medium text-foreground">{component.name}</span>
          <Badge variant="outline" className="shrink-0 px-1.5 py-0 text-[10px] text-muted-foreground">
            {isModel ? "model" : "dataset"}
          </Badge>
          <Badge variant="outline" className="shrink-0 px-1.5 py-0 text-[10px] text-muted-foreground">
            {component.source}
          </Badge>
        </div>
        {component.evidence && (
          <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
            {component.evidence}
          </div>
        )}
      </div>
      <div className="shrink-0 text-xs">
        {component.unpinned ? (
          // Deliberately amber, not green or red. An unpinned model is not
          // a vulnerability, but it is not fine either; the referenced
          // weights can change after review.
          <span
            className="text-chart-3"
            title="No revision pinned: the referenced model or dataset can change after review, so the artifact you audited is not necessarily the one you run."
          >
            unpinned
          </span>
        ) : (
          <span className="font-mono text-muted-foreground">{component.version}</span>
        )}
      </div>
    </ListRow>
  );
}

export function AiBomPanel({ targetId, targetName }: { targetId: number; targetName?: string }) {
  const state = useAsyncData<AiBomView>(() => api.aibom(targetId), { deps: [targetId] });

  return (
    <AsyncContent
      state={state}
      itemNoun="AI components"
      // "Never generated" and "generated, found nothing" are different facts
      // and must not render the same. A repo nobody has analysed reading as a
      // repo with no AI dependencies is exactly the false all-clear this
      // feature exists to prevent (same principle as #174's never-scanned
      // repos). Emptiness here therefore means "generated and found nothing";
      // the not-generated case is handled inside the render callback, because
      // only the payload knows which it is.
      isEmpty={(d) => d.generated && d.components.length === 0}
      emptyIcon={Boxes}
      emptyTitle="No models or datasets found"
      emptyDescription="This target was analysed and no model or dataset references were detected in its source."
    >
      {(data) =>
        !data.generated ? (
          <div className="rounded-lg border border-dashed border-border bg-card/40 px-6 py-12 text-center">
            <Boxes className="mx-auto h-6 w-6 text-muted-foreground" aria-hidden="true" />
            <p className="mt-3 text-sm font-medium text-foreground">No AIBOM generated yet</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Run an SBOM generation for this target; the AI bill of materials is extracted from the same
              checkout. Until then, whether this repo uses models or datasets is unknown, not none.
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
              <span>
                <span className="font-medium text-foreground">{data.summary.models}</span> model
                {data.summary.models === 1 ? "" : "s"}
              </span>
              <span>
                <span className="font-medium text-foreground">{data.summary.datasets}</span> dataset
                {data.summary.datasets === 1 ? "" : "s"}
              </span>
              {data.summary.unpinned > 0 && (
                <span className="text-chart-3">{data.summary.unpinned} unpinned</span>
              )}
              {data.summary.hosted_api_models > 0 && (
                <span title="Hosted API models have no pinnable revision from the caller's side; the provider can change what sits behind the name.">
                  {data.summary.hosted_api_models} hosted API
                </span>
              )}
              <a
                href={`/api/sbom/${targetId}/aibom/export`}
                className="ml-auto"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="outline" size="sm" className="h-7 text-xs">
                  Export CycloneDX 1.6
                </Button>
              </a>
            </div>

            <p className="text-[11px] text-muted-foreground">
              Training data, model lineage and licence are not declarable from source and are recorded as{" "}
              <span className="font-mono">unknown</span> in the exported document rather than omitted
              {targetName ? ` for ${targetName}` : ""}.
            </p>

            <ListRows>
              {data.components.map((c) => (
                <ComponentRow key={c.id} component={c} />
              ))}
            </ListRows>
          </div>
        )
      }
    </AsyncContent>
  );
}
