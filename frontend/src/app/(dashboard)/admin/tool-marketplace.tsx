"use client";

import { useMemo, useState } from "react";
import { api, ToolAssignment, ToolRegistryEntry } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { useToolInstall } from "@/hooks/use-tool-install";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { CheckCircle2, Download, ExternalLink, Loader2, XCircle } from "lucide-react";

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
// guardrail).
//
// Issue #216 added one-click install. The button appears only for tools the
// backend can actually install into itself (`installable`, derived from a
// pip package in the registry); everything needing brew/go/docker keeps the
// copyable command, because a button that cannot work is worse than no
// button. The endpoint takes a registry key rather than a package name --
// see app.core.tool_install for why that is what makes this safe.
export function ToolMarketplace() {
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [savingTool, setSavingTool] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);

  const {
    data: registry,
    error: registryError,
    refetch: refreshRegistry,
  } = useAsyncData<ToolRegistryEntry[]>(() => api.toolsRegistry());

  // Refresh the registry when an install settles so the tool's health check
  // and version re-run -- otherwise a freshly installed tool keeps showing
  // as missing until the admin reloads the page.
  const { installs, install, dismiss } = useToolInstall(() => refreshRegistry());


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
              const installState = installs[t.tool];
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
                        {/* CTX-03: this tool lives on the Celery worker, not
                            next to the web process. Scans run on the worker,
                            so it genuinely works -- but say which, rather
                            than implying the web process can see it. */}
                        {t.installed && t.checked_in === "worker" && (
                          <Badge variant="outline" className="border-muted-foreground/20 text-muted-foreground">
                            on scan worker
                          </Badge>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>{t.version ?? "—"}</span>
                      {t.response_ms !== null && <span>{t.response_ms}ms</span>}
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <div className="flex items-center justify-between gap-2 rounded-md bg-secondary/50 px-2 py-1.5">
                        {/* A bundled tool ships in the image, so showing it a
                            host install command (often `brew ...`, inside a
                            Debian container) is misleading twice over. */}
                        <code className="truncate text-xs text-foreground">
                          {t.bundled ? "Bundled in the backend image \u2014 no install needed" : t.install_cmd}
                        </code>
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

                      {t.installable && !t.installed && installState?.status !== "running" && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 w-full text-xs"
                          onClick={() => install(t.tool)}
                          aria-label={`Install ${t.display_name}`}
                        >
                          <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                          Install
                        </Button>
                      )}

                      {installState?.status === "running" && (
                        <div
                          role="status"
                          aria-live="polite"
                          className="flex items-center gap-1.5 px-1 text-xs text-muted-foreground"
                        >
                          <Loader2
                            className="h-3.5 w-3.5 shrink-0 animate-spin motion-reduce:animate-none"
                            aria-hidden="true"
                          />
                          Installing {t.display_name}...
                        </div>
                      )}

                      {installState?.status === "completed" && (
                        <p role="status" aria-live="polite" className="px-1 text-xs text-chart-5">
                          Installed{installState.version ? ` — ${installState.version}` : ""}
                        </p>
                      )}

                      {installState?.status === "failed" && (
                        <div className="flex flex-col gap-1 px-1">
                          {/* The real reason, not "Failed": "No matching
                              distribution" and "installed but does not run"
                              need different responses from an admin. */}
                          <p role="status" aria-live="polite" className="text-xs text-destructive">
                            {installState.error || "Install failed"}
                          </p>
                          <button
                            type="button"
                            onClick={() => dismiss(t.tool)}
                            className="self-start text-[11px] text-muted-foreground underline hover:text-foreground"
                          >
                            Dismiss
                          </button>
                        </div>
                      )}

                      {/* Stated rather than left to be discovered: this
                          installs into the running container, so a redeploy
                          reverts it. An admin who believes a scanner is
                          permanently installed when it is not gets silent
                          zero-finding scans after the next deploy. */}
                      {t.installable && (installState?.status === "completed" || (!t.installed && !installState)) && (
                        <p className="px-1 text-[11px] text-muted-foreground">
                          Installs into the running container — add it to the image to survive a redeploy.
                        </p>
                      )}
                    </div>

                    <div className="flex flex-col gap-1.5 border-t border-border pt-2">
                      <span className="text-xs font-medium text-foreground">
                        Usage assignment{assignment?.is_default ? " (default)" : ""}
                      </span>
                      {/* Says what ticking a box does. Previously four
                          unexplained checkboxes -- an external review flagged
                          that nothing stated whether they took effect, or (per
                          GH-01) whether they were honoured at all. */}
                      <p className="text-[11px] text-muted-foreground">
                        Which scans run {t.display_name}. Applies to the next scan; no re-scan is triggered.
                      </p>
                      {/* A registry-only tool has no runnable command, so an
                          enabled box here could never make it execute.
                          Ticking one anyway is the exact GH-01 failure:
                          a checked box for a tool that never runs. */}
                      {!t.integrated && (
                        <p className="text-[11px] text-muted-foreground">
                          Catalogued for visibility only — Rikugan cannot execute this tool yet, so these have no effect.
                        </p>
                      )}
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1">
                        {USAGE_SURFACES.map((s) => (
                          <label key={s.key} className="flex items-center gap-2 text-xs text-muted-foreground">
                            <input
                              type="checkbox"
                              aria-label={`${t.display_name} enabled for ${s.label}`}
                              className="h-3.5 w-3.5 accent-primary"
                              checked={assignment ? assignment[s.key] && t.integrated : false}
                              disabled={!assignment || savingTool === t.tool || !t.integrated}
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
