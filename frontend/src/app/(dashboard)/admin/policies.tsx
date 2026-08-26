"use client";

import { useState } from "react";
import { api, PolicyRule, PolicyRuleType, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { Building2, ScrollText, ShieldAlert, Trash2 } from "lucide-react";

const RULE_TYPES: { value: PolicyRuleType; label: string; placeholder: string }[] = [
  { value: "block_severity", label: "Block severity threshold", placeholder: "Critical / High / Medium / Low" },
  { value: "suppress_rule", label: "Suppress rule", placeholder: "rule_id (exact or substring)" },
  { value: "suppress_license", label: "Suppress license", placeholder: "e.g. MIT" },
];

function ruleLabel(t: PolicyRuleType) {
  return RULE_TYPES.find((r) => r.value === t)?.label ?? t;
}

export function Policies() {
  // Issue #118: this used to derive its workspace list from `targets`
  // (labeling each as `Workspace ${id} (${target.name})`, a raw,
  // target-name-based label unlike every other admin tab's clean
  // `workspace.name`). Switched to the same `api.workspaces()` source the
  // other 5 workspace pickers use, so the label format (and the duplicate-
  // "default"-workspace disambiguation via `workspaceDisplayName`) matches
  // everywhere.
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [mutationError, setMutationError] = useState<string | null>(null);

  const [ruleType, setRuleType] = useState<PolicyRuleType>("block_severity");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);

  const {
    data,
    error: loadError,
    isInitialLoading: loading,
    refetch,
  } = useAsyncData<PolicyRule[]>(() => api.listPolicies(workspaceId!), {
    enabled: workspaceId != null,
    deps: [workspaceId],
  });
  const rules = data ?? [];

  const error = mutationError ?? loadError?.message ?? workspacesError?.message ?? null;

  async function createRule() {
    if (!workspaceId || !value.trim()) return;
    setSaving(true);
    setMutationError(null);
    try {
      await api.createPolicy({ workspace_id: workspaceId, rule_type: ruleType, value: value.trim(), reason: reason.trim() });
      setValue("");
      setReason("");
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to create policy");
    } finally {
      setSaving(false);
    }
  }

  async function removeRule(id: number) {
    if (!workspaceId) return;
    try {
      await api.deletePolicy(id);
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to delete policy");
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Policy-as-code</div>
              <div className="text-xs text-muted-foreground">
                Severity thresholds and org-level suppression rules that adjust PR Guardrail&apos;s blocking decision.
                No rules configured means the default (Critical/High blocks) behavior applies.
              </div>
            </div>
          </div>

          {/* Loading is its own branch: before the migration a still-loading
              list hit the `length === 0` path and announced "No workspaces
              yet", which is a claim the page had not yet earned. */}
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
              aria-label="Workspace"
              className="w-fit rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={workspaceId ?? ""}
              onChange={(e) => setWorkspaceId(Number(e.target.value))}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {workspaceDisplayName(w, workspaces)}
                </option>
              ))}
            </select>
          )}

          {/* Outside the workspaceId guard on purpose: if the workspace list
              itself failed, there is no selected workspace, and an error
              rendered inside that guard would never appear. */}
          {error && <p className="text-xs text-destructive">{error}</p>}

          {workspaceId != null && (
            <>
              <div className="flex flex-wrap items-end gap-2">
                <select
                  className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                  value={ruleType}
                  onChange={(e) => setRuleType(e.target.value as PolicyRuleType)}
                >
                  {RULE_TYPES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
                <Input
                  className="w-56 bg-secondary"
                  placeholder={RULE_TYPES.find((r) => r.value === ruleType)?.placeholder}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                />
                <Input
                  className="w-56 bg-secondary"
                  placeholder="Reason (optional)"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
                <Button onClick={createRule} disabled={saving || !value.trim()} className="shrink-0">
                  {saving ? "Adding..." : "Add rule"}
                </Button>
              </div>

              <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                {loading ? (
                  <div className="px-3 py-2">
                    <SkeletonList count={2} />
                  </div>
                ) : rules.length === 0 ? (
                  <EmptyState
                    icon={ScrollText}
                    title="No active policy rules"
                    description="For this workspace."
                    bare
                  />
                ) : (
                  rules.map((r) => (
                    <div key={r.id} className="flex items-center justify-between gap-3 px-3 py-2">
                      <div className="flex flex-col">
                        <div className="text-sm text-foreground">
                          <span className="font-medium">{ruleLabel(r.rule_type)}</span>: {r.value}
                        </div>
                        {r.reason && <div className="text-xs text-muted-foreground">{r.reason}</div>}
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="shrink-0 text-muted-foreground hover:text-destructive"
                        onClick={() => removeRule(r.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
