"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, PipelineWorkflow } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// Issue #66: "Add Pipeline" flow -- preview the generated per-target
// GitHub Actions workflow, then open a real PR against the target's repo
// adding it, via the GitHub App. Integration status (pipeline_integrated /
// pipeline_pr_url) is read straight off the Target row so a page reload
// doesn't need to re-hit GitHub.
export function PipelineIntegration({
  targetId,
  initialIntegrated,
  initialPrUrl,
}: {
  targetId: number;
  initialIntegrated: boolean;
  initialPrUrl: string | null;
}) {
  const router = useRouter();
  const [integrated, setIntegrated] = useState(initialIntegrated);
  const [prUrl, setPrUrl] = useState(initialPrUrl);
  const [workflow, setWorkflow] = useState<PipelineWorkflow | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [integrating, setIntegrating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function togglePreview() {
    if (showPreview) {
      setShowPreview(false);
      return;
    }
    setShowPreview(true);
    if (workflow) return;
    setLoadingPreview(true);
    setError(null);
    try {
      const wf = await api.pipelineWorkflow(targetId);
      setWorkflow(wf);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to generate workflow preview");
    } finally {
      setLoadingPreview(false);
    }
  }

  async function integrate() {
    setIntegrating(true);
    setError(null);
    try {
      const res = await api.integratePipeline(targetId);
      if ("error" in res) {
        setError(res.error);
        return;
      }
      setIntegrated(res.pipeline_integrated);
      setPrUrl(res.pipeline_pr_url);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to open pipeline integration PR");
    } finally {
      setIntegrating(false);
    }
  }

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-medium text-foreground">CI/CD Pipeline Integration</h2>
            {integrated ? (
              <Badge variant="outline" className="border-chart-5/40 text-chart-5">
                Integrated
              </Badge>
            ) : (
              <Badge variant="outline" className="text-muted-foreground">
                Not integrated
              </Badge>
            )}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Generates a GitHub Actions workflow that runs Semgrep, Gitleaks, Trivy (and gosec for
            Go repos) natively in your CI and pushes results back into Rikugan, then opens a PR adding
            it to this repo.
          </p>
          {prUrl && (
            <a
              href={safeHref(prUrl)}
              target="_blank"
              rel="noreferrer"
              className="mt-1 inline-block text-xs text-accent-strong underline underline-offset-2"
            >
              View integration PR &rarr;
            </a>
          )}
        </div>
        <div className="flex shrink-0 gap-2">
          <Button size="sm" variant="outline" onClick={togglePreview}>
            {showPreview ? "Hide preview" : "Preview workflow"}
          </Button>
          <Button size="sm" onClick={integrate} disabled={integrating}>
            {integrating ? "Opening PR..." : integrated ? "Re-run integration" : "Add Pipeline"}
          </Button>
        </div>
      </div>

      {error && <p className="text-xs text-destructive">{error}</p>}

      {showPreview && (
        <div className="flex flex-col gap-2">
          {loadingPreview && <p className="text-xs text-muted-foreground">Generating...</p>}
          {workflow && (
            <>
              <p className="text-xs text-muted-foreground">
                Target: <code>{workflow.path}</code> · scanners:{" "}
                {workflow.includes_gosec ? "semgrep, gitleaks, trivy, gosec" : "semgrep, gitleaks, trivy"}
                {workflow.languages.length > 0 && ` (detected: ${workflow.languages.join(", ")})`}
              </p>
              <p className="text-xs text-chart-3">
                Requires the <code>RIKUGAN_API_URL</code> / <code>RIKUGAN_API_KEY</code> Actions secrets on
                the target repo. <code>RIKUGAN_API_URL</code> must be a publicly reachable Rikugan
                deployment -- GitHub&apos;s cloud runners cannot reach localhost.
              </p>
              <pre className="max-h-96 overflow-auto rounded-md bg-secondary p-3 text-[11px] leading-relaxed text-foreground">
                {workflow.yaml}
              </pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}
