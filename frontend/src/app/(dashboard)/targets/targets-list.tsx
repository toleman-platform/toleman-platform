"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Group, PipelineIntegrationBatch, PipelineWorkflowTemplate, Target, WorkspaceSummary, api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { GroupBadge } from "@/components/group-badge";
import { CriticalityChip } from "@/components/criticality-chip";
import { EmptyState } from "@/components/ui/empty-state";
import { pollUntilSettled } from "@/lib/poll";
import { Rocket, X } from "lucide-react";

const ITEM_STATUS_LABEL: Record<string, string> = {
  pending: "Queued",
  running: "Opening PR...",
  succeeded: "PR opened",
  failed: "Failed",
  already_integrated: "Already integrated",
};

function itemBadgeClass(status: string): string {
  switch (status) {
    case "succeeded":
      return "border-chart-5/40 text-chart-5";
    case "already_integrated":
      return "border-chart-2/40 text-chart-2";
    case "failed":
      return "border-destructive/40 text-destructive";
    case "running":
      return "border-chart-3/40 text-chart-3";
    default:
      return "text-muted-foreground";
  }
}

// Issue #68: multi-select wrapper around #66's per-target "Add Pipeline"
// mechanism (see targets/[id]/pipeline-integration.tsx). Checkbox selection
// + bulk action bar UX follows the established pattern in
// components/findings-list.tsx (findings' bulk-triage bar) rather than
// inventing a new one.
export function TargetsList({ targets }: { targets: Target[] }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [batch, setBatch] = useState<PipelineIntegrationBatch | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);

  // Issue #125: search/criticality applied client-side over the already
  // -fetched target list, same as targets-filter-bar.tsx's URL-param
  // convention -- group_id stays a separate server-refetching filter
  // (components/group-filter.tsx).
  const search = (searchParams.get("search") ?? "").trim().toLowerCase();
  const criticality = searchParams.get("criticality") ?? "";

  const filtered = useMemo(() => {
    return targets.filter((t) => {
      if (search) {
        const haystack = `${t.name} ${t.repo_url}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      if (criticality && t.label !== criticality) return false;
      return true;
    });
  }, [targets, search, criticality]);

  useEffect(() => {
    if (!batch || batch.status !== "running") return;
    const cancel = pollUntilSettled(
      () => api.getPipelineIntegrationBatch(batch.batch_id),
      (result) => setBatch(result),
      { onError: (err) => setBatchError(err instanceof Error ? err.message : "failed to poll batch status") }
    );
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch?.batch_id]);

  function toggleOne(id: number, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleAll(checked: boolean) {
    setSelected(checked ? new Set(filtered.map((t) => t.id)) : new Set());
  }

  async function addPipelineBulk() {
    if (selected.size === 0) return;
    setSubmitting(true);
    setBatchError(null);
    try {
      const res = await api.bulkPipelineIntegrate(Array.from(selected));
      setBatch({
        batch_id: res.batch_id,
        status: res.status,
        total: res.total,
        succeeded: 0,
        failed: 0,
        already_integrated: 0,
        started_at: new Date().toISOString(),
        completed_at: null,
        items: [],
      });
      setSelected(new Set());
    } catch (e) {
      setBatchError(e instanceof Error ? e.message : "failed to start bulk pipeline integration");
    } finally {
      setSubmitting(false);
    }
  }

  function closeBatchPanel() {
    setBatch(null);
    setBatchError(null);
    if (batch?.status === "completed") router.refresh();
  }

  // ---------------------------------------------------------------------
  // Issue #35: Mass CI/CD Rollout Engine -- scope-based sibling to the
  // manual multi-select bulk flow above. Instead of checking boxes, the
  // caller picks a whole workspace / repo Group / "every repo I can see"
  // and optionally a Custom Workflow Builder template (workflow-templates
  // tab in Admin); the backend resolves the scope into a target set and
  // reuses the exact same PipelineIntegrationBatch tracking + polling as
  // the bulk flow (batch state above is shared for both).
  // ---------------------------------------------------------------------
  const [massOpen, setMassOpen] = useState(false);
  const [massScope, setMassScope] = useState<"all" | "workspace" | "group">("workspace");
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[] | null>(null);
  const [massWorkspaceId, setMassWorkspaceId] = useState<number | "">("");
  const [groupsInWorkspace, setGroupsInWorkspace] = useState<Group[] | null>(null);
  const [massGroupId, setMassGroupId] = useState<number | "">("");
  const [templatesInWorkspace, setTemplatesInWorkspace] = useState<PipelineWorkflowTemplate[] | null>(null);
  const [massTemplateId, setMassTemplateId] = useState<number | "">("");
  const [massSubmitting, setMassSubmitting] = useState(false);
  const [massError, setMassError] = useState<string | null>(null);

  useEffect(() => {
    if (massOpen && workspaces === null) {
      api
        .workspaces()
        .then((list) => {
          setWorkspaces(list);
          if (list.length > 0) setMassWorkspaceId(list[0].id);
        })
        .catch((e) => setMassError(e instanceof Error ? e.message : "failed to load workspaces"));
    }
  }, [massOpen, workspaces]);

  useEffect(() => {
    if (massScope === "all" || massWorkspaceId === "") {
      setGroupsInWorkspace(null);
      setTemplatesInWorkspace(null);
      setMassGroupId("");
      setMassTemplateId("");
      return;
    }
    Promise.all([api.groups(massWorkspaceId), api.pipelineTemplates(massWorkspaceId)])
      .then(([g, t]) => {
        setGroupsInWorkspace(g);
        setTemplatesInWorkspace(t);
      })
      .catch((e) => setMassError(e instanceof Error ? e.message : "failed to load groups/templates"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [massScope, massWorkspaceId]);

  async function startMassRollout() {
    setMassError(null);
    if (massScope === "workspace" && massWorkspaceId === "") {
      setMassError("choose a workspace");
      return;
    }
    if (massScope === "group" && massGroupId === "") {
      setMassError("choose a group");
      return;
    }
    setMassSubmitting(true);
    try {
      const res = await api.massPipelineRollout({
        scope: massScope,
        workspace_id: massScope === "workspace" || massScope === "group" ? (massWorkspaceId as number) : undefined,
        group_id: massScope === "group" ? (massGroupId as number) : undefined,
        workflow_template_id: massTemplateId === "" ? undefined : (massTemplateId as number),
      });
      setBatch({
        batch_id: res.batch_id,
        status: res.status,
        total: res.total,
        succeeded: 0,
        failed: 0,
        already_integrated: 0,
        started_at: new Date().toISOString(),
        completed_at: null,
        items: [],
        scope_label: res.scope_label,
      });
      setMassOpen(false);
    } catch (e) {
      setMassError(e instanceof Error ? e.message : "failed to start mass rollout");
    } finally {
      setMassSubmitting(false);
    }
  }

  const allSelected = filtered.length > 0 && filtered.every((t) => selected.has(t.id));

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        {filtered.length > 0 ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              aria-label="Select all targets"
              className="h-4 w-4 accent-primary"
              checked={allSelected}
              onChange={(e) => toggleAll(e.target.checked)}
            />
            <span>
              Select all {(search || criticality) && `(${filtered.length} of ${targets.length} shown)`}
            </span>
          </div>
        ) : (
          <span />
        )}
        {/* Issue #35: fleet-wide alternative to the checkbox-driven bulk bar
            below -- rolls out to an entire workspace/group/every accessible
            repo without paging through a manual selection. */}
        <Button variant="outline" size="sm" onClick={() => setMassOpen((v) => !v)} className="h-7 text-xs">
          <Rocket className="mr-1 h-3.5 w-3.5" />
          Mass Rollout
        </Button>
      </div>

      {massOpen && (
        <div className="flex flex-col gap-3 rounded-md border border-border bg-card p-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-foreground">Mass CI/CD Rollout</span>
            <button onClick={() => setMassOpen(false)} aria-label="Close mass rollout" className="text-muted-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            Add the Rikugan pipeline scan workflow to every repo in a scope at once, instead of selecting them one
            by one.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
              value={massScope}
              onChange={(e) => setMassScope(e.target.value as typeof massScope)}
              aria-label="Rollout scope"
            >
              <option value="workspace">Entire workspace</option>
              <option value="group">A repo group</option>
              <option value="all">All repos I can access</option>
            </select>

            {(massScope === "workspace" || massScope === "group") && (
              <select
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={massWorkspaceId}
                onChange={(e) => setMassWorkspaceId(e.target.value === "" ? "" : Number(e.target.value))}
                aria-label="Workspace"
              >
                <option value="">Choose workspace...</option>
                {workspaces?.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name}
                  </option>
                ))}
              </select>
            )}

            {massScope === "group" && (
              <select
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={massGroupId}
                onChange={(e) => setMassGroupId(e.target.value === "" ? "" : Number(e.target.value))}
                aria-label="Repo group"
              >
                <option value="">Choose group...</option>
                {groupsInWorkspace?.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            )}

            {(massScope === "workspace" || massScope === "group") && templatesInWorkspace && templatesInWorkspace.length > 0 && (
              <select
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={massTemplateId}
                onChange={(e) => setMassTemplateId(e.target.value === "" ? "" : Number(e.target.value))}
                aria-label="Custom workflow template"
              >
                <option value="">Default scanner set</option>
                {templatesInWorkspace.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            )}

            <Button size="sm" disabled={massSubmitting} onClick={startMassRollout} className="h-9 text-xs">
              {massSubmitting ? "Starting..." : "Start Rollout"}
            </Button>
          </div>
          {massError && <p className="text-xs text-destructive">{massError}</p>}
        </div>
      )}

      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-secondary/50 p-3">
          <span className="text-xs font-medium text-foreground">{selected.size} selected</span>
          <Button size="sm" disabled={submitting} onClick={addPipelineBulk} className="h-7 text-xs">
            {submitting ? "Starting..." : `Add Pipeline to ${selected.size} repo${selected.size === 1 ? "" : "s"}`}
          </Button>
          <button onClick={() => setSelected(new Set())} className="text-xs text-muted-foreground underline">
            clear selection
          </button>
        </div>
      )}

      {batchError && <p className="text-xs text-destructive">{batchError}</p>}

      {batch && (
        <div className="flex flex-col gap-2 rounded-md border border-border bg-card p-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-foreground">
              {batch.status === "running" ? (
                <>Adding pipeline to {batch.total} repos...</>
              ) : (
                <>
                  Done: {batch.succeeded} succeeded, {batch.already_integrated} already integrated, {batch.failed}{" "}
                  failed
                </>
              )}
              {/* Issue #35: only set for a scope-based Mass Rollout batch --
                  "" for #68's original manual checkbox-selection batches. */}
              {batch.scope_label && (
                <span className="ml-2 text-xs font-normal text-muted-foreground">({batch.scope_label})</span>
              )}
            </div>
            <button onClick={closeBatchPanel} className="text-xs text-muted-foreground underline">
              {batch.status === "running" ? "hide" : "close"}
            </button>
          </div>
          {batch.items.length > 0 && (
            <ul className="flex flex-col gap-1">
              {batch.items.map((item) => (
                <li key={item.target_id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="text-foreground">{item.target_name ?? `target #${item.target_id}`}</span>
                  <div className="flex items-center gap-2">
                    {item.status === "failed" && item.error && (
                      <span className="max-w-xs truncate text-destructive" title={item.error}>
                        {item.error}
                      </span>
                    )}
                    {item.pr_url && (
                      <a href={item.pr_url} target="_blank" rel="noreferrer" className="text-accent-strong underline underline-offset-2">
                        PR
                      </a>
                    )}
                    <Badge variant="outline" className={`text-[10px] ${itemBadgeClass(item.status)}`}>
                      {ITEM_STATUS_LABEL[item.status] ?? item.status}
                    </Badge>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {batch.status === "running" && batch.items.length === 0 && (
            <p className="text-xs text-muted-foreground">Starting...</p>
          )}
        </div>
      )}

      {filtered.length === 0 && targets.length > 0 && (
        <EmptyState
          icon={Rocket}
          title="No targets match these filters"
          description="Try clearing search or the criticality filter."
        />
      )}

      {filtered.map((t) => (
        <Card key={t.id} className="border-border bg-card transition-colors hover:border-primary/40">
          <CardContent className="flex items-center gap-3 px-4 py-3">
            <input
              type="checkbox"
              aria-label={`Select ${t.name}`}
              className="h-4 w-4 shrink-0 accent-primary"
              checked={selected.has(t.id)}
              onChange={(e) => toggleOne(t.id, e.target.checked)}
              onClick={(e) => e.stopPropagation()}
            />
            <Link href={`/targets/${t.id}`} className="flex flex-1 items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-foreground">{t.name}</span>
                  <CriticalityChip label={t.label} />
                </div>
                <div className="text-xs text-muted-foreground">{t.repo_url}</div>
                {t.groups.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {t.groups.map((g) => (
                      <GroupBadge key={g.id} group={g} />
                    ))}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                {t.pipeline_integrated && (
                  <Badge variant="outline" className="border-chart-5/40 text-chart-5">
                    Pipeline integrated
                  </Badge>
                )}
                <span className="text-xs text-muted-foreground">weight {t.criticality_weight}</span>
              </div>
            </Link>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
