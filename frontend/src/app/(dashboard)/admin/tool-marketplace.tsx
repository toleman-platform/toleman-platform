"use client";

import { useMemo, useState } from "react";
import { api, ToolAssignment, ToolRegistryEntry } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { CheckCircle2, ExternalLink, XCircle } from "lucide-react";

const USAGE_SURFACES = [
  { key: "on_demand_scan" as const, label: "On-demand scan" },
  { key: "ci_pipeline" as const, label: "CI pipeline" },
  { key: "api_scan" as const, label: "API scan" },
  { key: "pr_guardrail" as const, label: "PR guardrail" },
];

const CATEGORY_ORDER = ["SAST", "SCA", "Secrets", "Container", "IaC", "License", "API/DAST", "AI/ML"];

// Issue #75: tool marketplace / health page. Extends the original Sprint 1
// Tools Health tab (still available separately at the "tools" admin tab,
// which /api/tools/health backs unchanged) with the full registry across
// every supported category (including the new IaC tools -- Checkov, tfsec,
// KICS), a real live health check per tool, and a per-workspace usage
// assignment matrix (on-demand scan / CI pipeline / API scan / PR
// guardrail). Deliberately no "install" button that executes anything --
// install_cmd is shown as copyable reference text; see
// app.core.tool_registry's module docstring for why literal remote package
// installation from a web request is out of scope here.
export function ToolMarketplace() {
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [savingTool, setSavingTool] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);

  const {
    data: registry,
    error: registryError,
    refetch: refreshRegistry,
  } = useAsyncData<ToolRegistryEntry[]>(() => api.toolsRegistry());

  const {
    data: assignments,
    error: assignmentsError,
    refetch: refreshAssignments,
  } = useAsyncData<Record<string, ToolAssignment>>(
    () => api.toolAssignments(workspaceId!).then((list) => Object.fromEntries(list.map((a) => [a.tool, a]))),
    { enabled: workspaceId != null, deps: [workspaceId] },
  );

  const error =
    mutationError ??
    registryError?.message ??
    assignmentsError?.message ??
    workspacesError?.message ??
    null;

  async function toggleSurface(tool: string, surface: (typeof USAGE_SURFACES)[number]["key"]) {
    if (!workspaceId || !assignments) return;
    const current = assignments[tool];
    if (!current) return;
    setSavingTool(tool);
    setMutationError(null);
    try {
      await api.saveToolAssignment({
        workspace_id: workspaceId,
        tool,
        on_demand_scan: current.on_demand_scan,
        ci_pipeline: current.ci_pipeline,
        api_scan: current.api_scan,
        pr_guardrail: current.pr_guardrail,
        [surface]: !current[surface],
      });
      refreshAssignments();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : `failed to update ${tool} usage assignment`);
    } finally {
      setSavingTool(null);
    }
  }

  const grouped = useMemo(() => {
    if (!registry) return null;
    const byCategory = new Map<string, ToolRegistryEntry[]>();
    for (const entry of registry) {
      const list = byCategory.get(entry.category) ?? [];
      list.push(entry);
      byCategory.set(entry.category, list);
    }
    const order = [...CATEGORY_ORDER, ...[...byCategory.keys()].filter((c) => !CATEGORY_ORDER.includes(c))];
    return order.filter((c) => byCategory.has(c)).map((c) => ({ category: c, tools: byCategory.get(c)! }));
  }, [registry]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-muted-foreground">
          Every supported OSS security tool across SAST, SCA, secrets, container, IaC, license, and AI/ML scanning, with a
          real <code className="text-foreground">--version</code> health check and per-workspace usage assignment.
          Installation is shown as a copyable command, not executed from the browser.
        </p>
        <div className="flex items-center gap-2">
          <label htmlFor="marketplace-workspace" className="text-xs text-muted-foreground">
            Workspace
          </label>
          <select
            id="marketplace-workspace"
            aria-label="Workspace for usage assignment"
            className="h-8 rounded-md border border-border bg-secondary px-2 text-xs text-foreground"
            value={workspaceId ?? ""}
            onChange={(e) => setWorkspaceId(Number(e.target.value))}
          >
            {workspaces?.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name}
              </option>
            ))}
          </select>
          <Button size="sm" variant="outline" onClick={refreshRegistry}>
            Recheck all
          </Button>
        </div>
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      {grouped === null && <SkeletonList count={4} />}

      {grouped?.map(({ category, tools }) => (
        <section key={category} aria-label={`${category} tools`} className="flex flex-col gap-3">
          <h2 className="text-sm font-semibold text-foreground">{category}</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {tools.map((t) => {
              const assignment = assignments?.[t.tool];
              return (
                <Card key={t.tool} className="border-border bg-card">
                  <CardContent className="flex flex-col gap-3 px-4 py-3">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-medium text-foreground">{t.display_name}</div>
                        <p className="mt-1 text-xs text-muted-foreground">{t.description}</p>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                        {t.installed && t.version ? (
                          <Badge variant="outline" className="border-chart-5/20 bg-chart-5/10 text-chart-5">
                            <CheckCircle2 className="h-3 w-3" /> healthy
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-destructive/20 bg-destructive/10 text-destructive">
                            <XCircle className="h-3 w-3" /> {t.installed ? "error" : "not installed"}
                          </Badge>
                        )}
                        {!t.integrated && (
                          <Badge variant="outline" className="border-muted-foreground/20 text-muted-foreground">
                            registry only
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>{t.version ?? "—"}</span>
                      {t.response_ms !== null && <span>{t.response_ms}ms</span>}
                    </div>

                    <div className="flex items-center justify-between gap-2 rounded-md bg-secondary/50 px-2 py-1.5">
                      <code className="truncate text-xs text-foreground">{t.install_cmd}</code>
                      <a
                        href={t.docs_url}
                        target="_blank"
                        rel="noreferrer"
                        aria-label={`${t.display_name} installation docs`}
                        className="shrink-0 text-muted-foreground hover:text-foreground"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </div>

                    <div className="flex flex-col gap-1.5 border-t border-border pt-2">
                      <span className="text-xs font-medium text-foreground">
                        Usage assignment{assignment?.is_default ? " (default)" : ""}
                      </span>
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1">
                        {USAGE_SURFACES.map((s) => (
                          <label key={s.key} className="flex items-center gap-2 text-xs text-muted-foreground">
                            <input
                              type="checkbox"
                              aria-label={`${t.display_name} enabled for ${s.label}`}
                              className="h-3.5 w-3.5 accent-primary"
                              checked={assignment ? assignment[s.key] : false}
                              disabled={!assignment || savingTool === t.tool}
                              onChange={() => toggleSurface(t.tool, s.key)}
                            />
                            {s.label}
                          </label>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}
