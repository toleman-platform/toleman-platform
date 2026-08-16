"use client";

import { useEffect, useState } from "react";
import { Boxes, Database } from "lucide-react";
import { AiBomComponent, AiBomView, api } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { SkeletonList } from "@/components/ui/skeleton";

// Issue #190: models and datasets a target depends on -- the part a package
// SBOM is blind to. Reads persisted rows populated during SBOM generation, so
// this reflects the last run without re-scanning, same as the Components tab.
function ComponentRow({ component }: { component: AiBomComponent }) {
  const isModel = component.component_type === "machine-learning-model";
  const Icon = isModel ? Boxes : Database;
  return (
    <Card className="border-border bg-card py-0">
      <CardContent
        className="flex items-center gap-3 px-4"
        style={{ paddingTop: "var(--density-row-py)", paddingBottom: "var(--density-row-py)" }}
      >
        <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
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
            // a vulnerability, but it is not fine either -- the referenced
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
      </CardContent>
    </Card>
  );
}

export function AiBomPanel({ targetId, targetName }: { targetId: number; targetName?: string }) {
  const [data, setData] = useState<AiBomView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .aibom(targetId)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "failed to load AIBOM");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [targetId]);

  if (loading) return <SkeletonList count={3} />;
  if (error) return <ErrorState description={error} />;
  if (!data) return null;

  // "Never generated" and "generated, found nothing" are different facts and
  // must not render the same. A repo nobody has analysed reading as a repo
  // with no AI dependencies is exactly the false all-clear this feature
  // exists to prevent (same principle as #174's never-scanned repos).
  if (!data.generated) {
    return (
      <EmptyState
        icon={Boxes}
        title="No AIBOM generated yet"
        description="Run an SBOM generation for this target — the AI bill of materials is extracted from the same checkout. Until then, whether this repo uses models or datasets is unknown, not none."
      />
    );
  }

  if (data.components.length === 0) {
    return (
      <EmptyState
        icon={Boxes}
        title="No models or datasets found"
        description="This target was analysed and no model or dataset references were detected in its source."
      />
    );
  }

  const { summary } = data;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
        <span>
          <span className="font-medium text-foreground">{summary.models}</span> model
          {summary.models === 1 ? "" : "s"}
        </span>
        <span>
          <span className="font-medium text-foreground">{summary.datasets}</span> dataset
          {summary.datasets === 1 ? "" : "s"}
        </span>
        {summary.unpinned > 0 && (
          <span className="text-chart-3">{summary.unpinned} unpinned</span>
        )}
        {summary.hosted_api_models > 0 && (
          <span title="Hosted API models have no pinnable revision from the caller's side — the provider can change what sits behind the name.">
            {summary.hosted_api_models} hosted API
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

      <div className="flex flex-col" style={{ gap: "var(--density-list-gap)" }}>
        {data.components.map((c) => (
          <ComponentRow key={c.id} component={c} />
        ))}
      </div>
    </div>
  );
}
