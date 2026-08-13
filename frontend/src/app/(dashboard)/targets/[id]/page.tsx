import { api } from "@/lib/api";
import { ScanButtons } from "./scan-buttons";
import { FindingRow } from "@/components/finding-row";
import { TargetGroups } from "./target-groups";
import { PipelineIntegration } from "./pipeline-integration";
import { TargetEnforcement } from "./target-enforcement";

export default async function TargetDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const targetId = Number(id);
  const [target, findingsResult] = await Promise.all([
    api.target(targetId),
    api.findings({ target_id: targetId, page_size: 500 }),
  ]);
  const findings = findingsResult.items;

  return (
    <div className="flex flex-col gap-8">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">{target.name}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{target.repo_url}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {target.label} · criticality weight {target.criticality_weight} · branch {target.default_branch}
          </p>
        </div>
        <ScanButtons targetId={targetId} />
      </div>

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

      <PipelineIntegration
        targetId={targetId}
        initialIntegrated={target.pipeline_integrated}
        initialPrUrl={target.pipeline_pr_url}
      />

      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">Findings ({findings.length})</h2>
        <div className="flex flex-col gap-2">
          {findings.map((f) => (
            <FindingRow key={f.id} finding={f} repoUrl={target.repo_url} />
          ))}
          {findings.length === 0 && (
            <p className="text-sm text-muted-foreground">No findings yet. Run a scan above.</p>
          )}
        </div>
      </div>
    </div>
  );
}
