"use client";

import { useState } from "react";
import { api, PolicyRule, PolicyRuleType } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Building2, ScrollText, ShieldAlert, Trash2 } from "lucide-react";

// M14: the three rule types used to be a bare `<select>` of their own
// labels ("Block severity threshold", "Suppress rule", "Suppress license")
// with nothing said about what picking one actually does. That matters here
// specifically because the three behave nothing alike -- one changes a
// *threshold* (findings stay visible; PR Guardrail's blocking line moves)
// and two *remove findings from every scan in the workspace outright* -- and
// a reader guessing wrong picks the kind of rule that quietly hides a class
// of finding when they meant to only stop blocking PRs on it. `description`
// mirrors app/core/policy.py's own docstring and matching logic (the
// mechanism actually applied server-side) rather than restating the label in
// other words, which is how this kind of copy drifts from what the code does.
// The exact values the PR Guardrail engine matches a BLOCK_SEVERITY policy
// against. Must stay identical to SEVERITY_ORDER in
// backend/app/core/pr_guardrail.py: the comparison there is `in SEVERITY_ORDER`,
// so a casing or spelling difference produces a policy that is stored and
// listed but never applied.
const BLOCK_SEVERITY_VALUES = ["Critical", "High", "Medium", "Low", "Informational"] as const;

const RULE_TYPES: { value: PolicyRuleType; label: string; placeholder: string; description: string }[] = [
  {
    value: "block_severity",
    label: "Block severity threshold",
    placeholder: "Critical / High / Medium / Low",
    description:
      "Findings stay visible either way -- this only moves the bar for which severities make PR " +
      "Guardrail block a pull request. Set to Medium and Medium/High/Critical all block; Low and " +
      "everything blocks. With more than one active rule, the lowest (most permissive-to-block) wins.",
  },
  {
    value: "suppress_rule",
    label: "Suppress rule",
    placeholder: "rule_id (exact or substring)",
    description:
      "Removes every finding whose rule_id matches this value (exact match, or a substring match in " +
      "either direction) from every scan in the workspace, not just this PR. Use it for a specific check " +
      "that's wrong for this codebase; a suppressed finding stops surfacing anywhere until this rule is " +
      "deleted, so there's no per-finding undo.",
  },
  {
    value: "suppress_license",
    label: "Suppress license",
    placeholder: "e.g. MIT",
    description:
      "Same effect as Suppress rule, scoped to a license name instead of a rule_id: allow-lists a " +
      "license (e.g. MIT) the team has already reviewed, removing its findings workspace-wide rather " +
      "than only from this PR.",
  },
];

function ruleLabel(t: PolicyRuleType) {
  return RULE_TYPES.find((r) => r.value === t)?.label ?? t;
}

export function Policies() {
  // (#506) Follows the global workspace switcher instead of owning its own
  // picker; policy rules are per-workspace, so a null activeWorkspaceId
  // ("All workspaces") renders a prompt below rather than fetching anything.
  const { activeWorkspaceId: workspaceId, error: workspacesError } = useWorkspaceContext();
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

  // Deleting a policy rule changes what PR Guardrail blocks for the whole
  // workspace and can't be undone; it used to mutate on click from an
  // icon-only button with no accessible name at all.
  const [pendingDelete, setPendingDelete] = useState<PolicyRule | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function removeRule(id: number) {
    if (!workspaceId) return;
    setDeleting(true);
    try {
      await api.deletePolicy(id);
      setPendingDelete(null);
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to delete policy");
    } finally {
      setDeleting(false);
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

          {workspaceId == null && (
            <EmptyState
              icon={Building2}
              title="Pick a workspace"
              description="Policy rules are per-workspace; choose one from the switcher in the sidebar to view them."
              bare
            />
          )}

          {/* Outside the workspaceId guard on purpose: if the workspace list
              itself failed, there is no selected workspace, and an error
              rendered inside that guard would never appear. */}
          {error && <p className="text-xs text-destructive">{error}</p>}

          {workspaceId != null && (
            <>
              <div className="flex flex-wrap items-end gap-2">
                <select
                  aria-label="Rule type"
                  className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                  value={ruleType}
                  onChange={(e) => {
                    setRuleType(e.target.value as PolicyRuleType);
                    // The value means something different per rule type; carrying
                    // "Critical" into a rule_id field would submit a rule that
                    // matches nothing.
                    setValue("");
                  }}
                >
                  {RULE_TYPES.map((r) => (
                    <option key={r.value} value={r.value} title={r.description}>
                      {r.label}
                    </option>
                  ))}
                </select>
                {ruleType === "block_severity" ? (
                  // A threshold is matched server-side by exact, case-sensitive
                  // membership of SEVERITY_ORDER (backend/app/core/pr_guardrail.py).
                  // As free text this accepted "critical", saved it, listed it as
                  // an active policy, and then silently fell back to the default
                  // blocking set -- so the rule an admin had just written did
                  // nothing and nothing said so. A fixed set is the only input
                  // here that cannot express a rule the engine will ignore.
                  <select
                    aria-label="Block severity threshold"
                    className="w-56 rounded-md border border-input bg-secondary px-3 py-1.5 text-sm text-foreground"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                  >
                    <option value="">Select a severity...</option>
                    {BLOCK_SEVERITY_VALUES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                ) : (
                  <Input
                    className="w-56 bg-secondary"
                    aria-label={RULE_TYPES.find((r) => r.value === ruleType)?.label}
                    placeholder={RULE_TYPES.find((r) => r.value === ruleType)?.placeholder}
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                  />
                )}
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
              {/* M14: says what the *selected* type does, not just its name --
                  see RULE_TYPES above for why that distinction matters here. */}
              <p className="max-w-prose text-xs text-muted-foreground">
                {RULE_TYPES.find((r) => r.value === ruleType)?.description}
              </p>

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
                        onClick={() => setPendingDelete(r)}
                        aria-label={`Delete policy rule ${ruleLabel(r.rule_type)}: ${r.value}`}
                        title="Delete rule"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))
                )}
              </div>

              <ConfirmDialog
                open={pendingDelete !== null}
                title="Delete this policy rule?"
                description={
                  <>
                    <strong>
                      {pendingDelete ? `${ruleLabel(pendingDelete.rule_type)}: ${pendingDelete.value}` : ""}
                    </strong>{" "}
                    stops applying to this workspace immediately, and PR Guardrail&apos;s blocking decision changes
                    accordingly &mdash; with no rules left, the default Critical/High-blocks behavior applies. This
                    can&apos;t be undone.
                  </>
                }
                confirmLabel="Delete rule"
                tone="destructive"
                loading={deleting}
                onConfirm={() => pendingDelete && removeRule(pendingDelete.id)}
                onCancel={() => setPendingDelete(null)}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
