import { jsonFetch } from "./client";
import type {
  Target,
  TargetSummary,
  GroupBadge,
  Group,
  EnforcementMode,
  PipelineWorkflow,
  PipelineIntegrateResult,
  PipelineIntegrationBatch,
  PipelineWorkflowTemplate,
  PipelineWorkflowStep,
  RunStatus,
} from "@/types";
import type { Nullable } from "@/std-lib";

/**
 * Lists all target repositories, optionally filtered by group ID.
 */
export function targets(query: { group_id?: number } = {}): Promise<Target[]> {
  const params = new URLSearchParams();
  if (query.group_id) params.set("group_id", String(query.group_id));
  const qs = params.toString();
  return jsonFetch<Target[]>(`/api/targets${qs ? `?${qs}` : ""}`);
}

/**
 * Retrieves full details for a single target repository, including effective enforcement mode.
 */
export function target(id: number): Promise<Target> {
  return jsonFetch<Target>(`/api/targets/${id}`);
}

/**
 * Creates a new target repository in the platform.
 */
export function createTarget(t: Partial<Target>): Promise<Target> {
  return jsonFetch<Target>("/api/targets", {
    method: "POST",
    body: JSON.stringify(t),
  });
}

/**
 * Updates properties on an existing target repository.
 */
export function updateTarget(id: number, patch: Partial<Target>): Promise<Target> {
  return jsonFetch<Target>(`/api/targets/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * Returns open-finding counts by severity across all targets.
 */
export function targetsSummary(): Promise<TargetSummary> {
  return jsonFetch<TargetSummary>("/api/targets/summary");
}

/**
 * Retrieves the groups assigned to a specific target.
 */
export function targetGroups(targetId: number): Promise<GroupBadge[]> {
  return jsonFetch<GroupBadge[]>(`/api/targets/${targetId}/groups`);
}

/**
 * Assigns a target to a group.
 */
export function assignTargetGroup(targetId: number, groupId: number): Promise<GroupBadge[]> {
  return jsonFetch<GroupBadge[]>(`/api/targets/${targetId}/groups/${groupId}`, { method: "POST" });
}

/**
 * Removes a target from a group.
 */
export function removeTargetGroup(targetId: number, groupId: number): Promise<GroupBadge[]> {
  return jsonFetch<GroupBadge[]>(`/api/targets/${targetId}/groups/${groupId}`, { method: "DELETE" });
}

/**
 * Lists all target groups within a workspace.
 */
export function groups(workspaceId?: number): Promise<Group[]> {
  return jsonFetch<Group[]>(`/api/groups${workspaceId ? `?workspace_id=${workspaceId}` : ""}`);
}

/**
 * Creates a new group within a workspace.
 */
export function createGroup(g: { workspace_id: number; name: string; color?: string }): Promise<Group> {
  return jsonFetch<Group>("/api/groups", {
    method: "POST",
    body: JSON.stringify(g),
  });
}

/**
 * Updates group properties (name, color, or enforcement mode override).
 */
export function updateGroup(
  id: number,
  patch: { name?: string; color?: string; enforcement_mode?: Nullable<EnforcementMode> },
): Promise<Group> {
  return jsonFetch<Group>(`/api/groups/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * Deletes a group from a workspace.
 */
export function deleteGroup(id: number): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>(`/api/groups/${id}`, { method: "DELETE" });
}

/**
 * Generates the target-specific CI/CD workflow YAML.
 */
export function pipelineWorkflow(targetId: number): Promise<PipelineWorkflow> {
  return jsonFetch<PipelineWorkflow>(`/api/targets/${targetId}/pipeline-workflow`);
}

/**
 * Opens a pull request against the target's GitHub repository adding the scanning workflow.
 */
export function integratePipeline(
  targetId: number,
  force = false,
): Promise<PipelineIntegrateResult | { error: string }> {
  return jsonFetch<PipelineIntegrateResult | { error: string }>(
    `/api/targets/${targetId}/pipeline-integrate${force ? "?force=true" : ""}`,
    {
      method: "POST",
    },
  );
}

/**
 * Dispatches an asynchronous batch integration job for multiple targets.
 */
export function bulkPipelineIntegrate(
  targetIds: number[],
  force = false,
  workflowTemplateId?: number,
): Promise<{ batch_id: number; total: number; status: RunStatus }> {
  return jsonFetch<{ batch_id: number; total: number; status: RunStatus }>("/api/targets/bulk-pipeline-integrate", {
    method: "POST",
    body: JSON.stringify({ target_ids: targetIds, force, workflow_template_id: workflowTemplateId }),
  });
}

/**
 * Polls the status and per-target outcomes of a pipeline integration batch.
 */
export function getPipelineIntegrationBatch(batchId: number): Promise<PipelineIntegrationBatch> {
  return jsonFetch<PipelineIntegrationBatch>(`/api/targets/bulk-pipeline-integrate/${batchId}`);
}

/**
 * Triggers a mass rollout of CI/CD scanning workflows across a workspace or group scope.
 */
export function massPipelineRollout(payload: {
  scope: "workspace" | "group" | "all";
  workspace_id?: number;
  group_id?: number;
  workflow_template_id?: number;
  force?: boolean;
}): Promise<{ batch_id: number; total: number; status: RunStatus; scope_label: string }> {
  return jsonFetch<{ batch_id: number; total: number; status: RunStatus; scope_label: string }>(
    "/api/targets/mass-pipeline-rollout",
    { method: "POST", body: JSON.stringify(payload) },
  );
}

/**
 * Lists reusable workflow templates configured for a workspace.
 */
export function pipelineTemplates(workspaceId?: number): Promise<PipelineWorkflowTemplate[]> {
  return jsonFetch<PipelineWorkflowTemplate[]>(
    `/api/pipeline-templates${workspaceId ? `?workspace_id=${workspaceId}` : ""}`,
  );
}

/**
 * Creates a custom CI/CD workflow template.
 */
export function createPipelineTemplate(t: {
  workspace_id: number;
  name: string;
  steps: PipelineWorkflowStep[];
}): Promise<PipelineWorkflowTemplate> {
  return jsonFetch<PipelineWorkflowTemplate>("/api/pipeline-templates", {
    method: "POST",
    body: JSON.stringify(t),
  });
}

/**
 * Updates a custom workflow template.
 */
export function updatePipelineTemplate(
  id: number,
  patch: { name?: string; steps?: PipelineWorkflowStep[] },
): Promise<PipelineWorkflowTemplate> {
  return jsonFetch<PipelineWorkflowTemplate>(`/api/pipeline-templates/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * Deletes a workflow template.
 */
export function deletePipelineTemplate(id: number): Promise<{ deleted: boolean }> {
  return jsonFetch<{ deleted: boolean }>(`/api/pipeline-templates/${id}`, { method: "DELETE" });
}
