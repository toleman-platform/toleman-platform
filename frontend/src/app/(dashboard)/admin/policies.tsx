"use client";

import { useEffect, useState } from "react";
import { api, PolicyRule, PolicyRuleType, Target } from "@/lib/api";
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
  const [workspaces, setWorkspaces] = useState<{ id: number; name: string }[]>([]);
  const [workspaceId, setWorkspaceId] = useState<number | null>(null);
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [ruleType, setRuleType] = useState<PolicyRuleType>("block_severity");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.targets().then((targets: Target[]) => {
      const byId = new Map<number, { id: number; name: string }>();
      for (const t of targets) {
        if (!byId.has(t.workspace_id)) {
          byId.set(t.workspace_id, { id: t.workspace_id, name: `Workspace ${t.workspace_id} (${t.name})` });
        }
      }
      const list = Array.from(byId.values());
      setWorkspaces(list);
      if (list.length > 0) setWorkspaceId(list[0].id);
    });
  }, []);

  function refresh(wsId: number) {
    setLoading(true);
    api
      .listPolicies(wsId)
      .then(setRules)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load policies"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (workspaceId != null) refresh(workspaceId);
  }, [workspaceId]);

  async function createRule() {
    if (!workspaceId || !value.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await api.createPolicy({ workspace_id: workspaceId, rule_type: ruleType, value: value.trim(), reason: reason.trim() });
      setValue("");
      setReason("");
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create policy");
    } finally {
      setSaving(false);
    }
  }

  async function removeRule(id: number) {
    if (!workspaceId) return;
    try {
      await api.deletePolicy(id);
      refresh(workspaceId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete policy");
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

          {workspaces.length === 0 ? (
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
              onChange={(e) => setWorkspaceId(Number(e.target.value))}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </select>
          )}

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

              {error && <p className="text-xs text-destructive">{error}</p>}

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
