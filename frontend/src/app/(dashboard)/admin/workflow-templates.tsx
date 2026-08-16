"use client";

import { useEffect, useState } from "react";
import { api, PIPELINE_WORKFLOW_TOOLS, PipelineWorkflowStep, PipelineWorkflowTemplate, WorkspaceSummary, workspaceDisplayName } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ArrowUp, ArrowDown, Building2, GitBranch, Trash2, Pencil, Save, Workflow, X } from "lucide-react";

// Custom Workflow Builder (issue #35): workspace-scoped named, ordered
// scanner step lists (semgrep/gitleaks/trivy/gosec, toggle + reorder) used
// by the Mass CI/CD Rollout Engine (targets-list.tsx's "Mass Rollout"
// dialog) instead of #66's fixed default scanner set. Deliberately a
// structured checkbox+reorder editor over the known scanner catalog, not a
// drag-and-drop arbitrary-DAG builder -- mirrors the up/down-button reorder
// UX already established for the dashboard widget list
// (components/dashboard/widget-shell.tsx), same "plain buttons, not a drag
// library" convention. Same workspace-picker-then-CRUD-list shape as the
// SLA Rules tab (sla-rules.tsx).

const TOOL_LABEL: Record<string, string> = {
  semgrep: "Semgrep (SAST)",
  gitleaks: "Gitleaks (secrets)",
  trivy: "Trivy (SCA/container)",
  gosec: "gosec (Go SAST)",
};

function defaultSteps(): PipelineWorkflowStep[] {
  return PIPELINE_WORKFLOW_TOOLS.map((tool) => ({ tool, enabled: tool !== "gosec" }));
}

function StepEditor({ steps, onChange }: { steps: PipelineWorkflowStep[]; onChange: (s: PipelineWorkflowStep[]) => void }) {
  function toggle(i: number) {
    const next = steps.map((s, idx) => (idx === i ? { ...s, enabled: !s.enabled } : s));
    onChange(next);
  }
  function move(i: number, dir: -1 | 1) {
    const j = i + dir;
    if (j < 0 || j >= steps.length) return;
    const next = [...steps];
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  }
  return (
    <ul className="flex flex-col gap-1" aria-label="Workflow steps, in run order">
      {steps.map((step, i) => (
        <li
          key={step.tool}
          className="flex items-center justify-between gap-2 rounded-md border border-border bg-secondary/40 px-3 py-2"
        >
          <label className="flex items-center gap-2 text-sm text-foreground">
            <input
              type="checkbox"
              className="h-4 w-4 accent-primary"
              checked={step.enabled}
              onChange={() => toggle(i)}
              aria-label={`Include ${TOOL_LABEL[step.tool] ?? step.tool} job`}
            />
            {TOOL_LABEL[step.tool] ?? step.tool}
          </label>
          <div className="flex items-center gap-1">
            <button
              type="button"
              aria-label={`Move ${step.tool} up`}
              disabled={i === 0}
              onClick={() => move(i, -1)}
              className="rounded p-1 text-muted-foreground hover:bg-secondary hover:text-foreground disabled:opacity-30"
            >
              <ArrowUp className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              aria-label={`Move ${step.tool} down`}
              disabled={i === steps.length - 1}
              onClick={() => move(i, 1)}
              className="rounded p-1 text-muted-foreground hover:bg-secondary hover:text-foreground disabled:opacity-30"
            >
              <ArrowDown className="h-3.5 w-3.5" />
            </button>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function WorkflowTemplates() {
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[] | null>(null);
  const [workspaceId, setWorkspaceId] = useState<number | null>(null);
  const [templates, setTemplates] = useState<PipelineWorkflowTemplate[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [steps, setSteps] = useState<PipelineWorkflowStep[]>(defaultSteps());
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);

  useEffect(() => {
    api.workspaces().then((list) => {
      setWorkspaces(list);
      if (list.length > 0) setWorkspaceId(list[0].id);
    });
  }, []);

  function refresh(wsId: number) {
    setLoading(true);
    api
      .pipelineTemplates(wsId)
      .then(setTemplates)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load workflow templates"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (workspaceId != null) refresh(workspaceId);
  }, [workspaceId]);

  function resetForm() {
    setName("");
    setSteps(defaultSteps());
    setEditingId(null);
  }

  async function save() {
    if (!workspaceId || !name.trim()) {
      setError("Name is required");
      return;
    }
    if (!steps.some((s) => s.enabled)) {
      setError("At least one step must be enabled");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      if (editingId != null) {
        await api.updatePipelineTemplate(editingId, { name: name.trim(), steps });
      } else {
        await api.createPipelineTemplate({ workspace_id: workspaceId, name: name.trim(), steps });
      }
      resetForm();
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save workflow template");
    } finally {
      setSaving(false);
    }
  }

  function edit(t: PipelineWorkflowTemplate) {
    setEditingId(t.id);
    setName(t.name);
    setSteps(t.steps);
  }

  async function remove(id: number) {
    if (!workspaceId) return;
    try {
      await api.deletePipelineTemplate(id);
      if (editingId === id) resetForm();
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete workflow template");
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <GitBranch className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Custom Workflow Builder</div>
              <div className="text-xs text-muted-foreground">
                Named, ordered scanner step lists for CI/CD pipeline rollout -- pick which of Rikugan&apos;s
                scanners run (and in what order) instead of the default full set. Used by Mass Rollout on
                the Targets page.
              </div>
            </div>
          </div>

          {workspaces === null ? (
            <SkeletonList count={1} />
          ) : workspaces.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="No workspaces yet"
              description="Connect a target first to create a workspace."
              bare
            />
          ) : (
            <select
              className="w-fit rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={workspaceId ?? ""}
              onChange={(e) => {
                resetForm();
                setWorkspaceId(Number(e.target.value));
              }}
              aria-label="Workspace"
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {workspaceDisplayName(w, workspaces)}
                </option>
              ))}
            </select>
          )}

          {workspaceId != null && (
            <>
              <div className="flex flex-col gap-3 rounded-md border border-border p-3">
                <div className="flex items-center gap-2">
                  <Input
                    className="max-w-xs bg-secondary"
                    placeholder="Template name (e.g. Fast, Full Audit)"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    aria-label="Template name"
                  />
                  {editingId != null && (
                    <Button variant="ghost" size="sm" onClick={resetForm} className="h-9 text-xs">
                      <X className="mr-1 h-3.5 w-3.5" /> cancel edit
                    </Button>
                  )}
                </div>
                <StepEditor steps={steps} onChange={setSteps} />
                <Button onClick={save} disabled={saving} className="w-fit">
                  <Save className="mr-1 h-3.5 w-3.5" />
                  {saving ? "Saving..." : editingId != null ? "Update Template" : "Create Template"}
                </Button>
              </div>

              {error && <p className="text-xs text-destructive">{error}</p>}

              {loading ? (
                <SkeletonList count={2} />
              ) : templates && templates.length > 0 ? (
                <ul className="flex flex-col gap-2">
                  {templates.map((t) => (
                    <li
                      key={t.id}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-secondary/30 px-3 py-2"
                    >
                      <div className="flex flex-col gap-1">
                        <span className="text-sm font-medium text-foreground">{t.name}</span>
                        <div className="flex flex-wrap gap-1">
                          {t.steps
                            .filter((s) => s.enabled)
                            .map((s) => (
                              <Badge key={s.tool} variant="outline" className="text-[10px]">
                                {s.tool}
                              </Badge>
                            ))}
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        <Button variant="ghost" size="sm" onClick={() => edit(t)} aria-label={`Edit ${t.name}`}>
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => remove(t.id)}
                          aria-label={`Delete ${t.name}`}
                          className="text-destructive hover:text-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState
                  icon={Workflow}
                  title="No custom workflow templates yet"
                  description="For this workspace -- Mass Rollout uses the default scanner set until you create one."
                />
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
