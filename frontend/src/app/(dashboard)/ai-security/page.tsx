"use client";

import Link from "next/link";
import { Bot, Boxes, Radar, ShieldOff } from "lucide-react";
import { api, Target } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { StatCard } from "@/components/ui/stat-card";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonList } from "@/components/ui/skeleton";

// Issue #224: AI/ML repo detection (#185), ModelScan (#186) and the LLM
// SAST ruleset (#189) shipped with zero dedicated frontend surface -- the
// only way to see any of it was to already know to look at a target's
// Vulnerabilities tab and filter by tool by hand. This page is the missing
// entry point: which repos got flagged, what those two AI-specific scanners
// found in them, and an honest "not yet available" for garak (#191) rather
// than pretending LLM red-teaming exists.
type AiTool = "modelscan" | "semgrep-llm";

export default function AiSecurityPage() {
  const { data: targets, error: targetsError, isInitialLoading: targetsLoading } = useAsyncData<Target[]>(
    () => api.targets()
  );

  // Two org-wide queries, one per AI-specific tool, then grouped by target
  // client-side -- the same shape sbom/page.tsx already uses for its OSS
  // Vulnerabilities tab (api.findings({ tool, page_size: 500 })). No
  // dedicated aggregate endpoint exists yet, and these two tools only ever
  // run against the handful of AI-flagged repos, so this stays cheap.
  const { data: modelscanFindings, isInitialLoading: modelscanLoading } = useAsyncData(
    () => api.findings({ tool: "modelscan", page_size: 500 }).then((r) => r.items)
  );
  const { data: semgrepLlmFindings, isInitialLoading: semgrepLlmLoading } = useAsyncData(
    () => api.findings({ tool: "semgrep-llm", page_size: 500 }).then((r) => r.items)
  );

  const loading = targetsLoading || modelscanLoading || semgrepLlmLoading;
  const aiTargets = (targets ?? []).filter((t) => t.is_ai_repo_effective);

  function countFor(tool: AiTool, targetId: number): number {
    const findings = tool === "modelscan" ? modelscanFindings : semgrepLlmFindings;
    return (findings ?? []).filter((f) => f.target_id === targetId).length;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">AI Security</h1>
        <p className="text-sm text-muted-foreground">
          Repos detected as using AI/ML, and what ModelScan and Toleman&apos;s LLM ruleset found in them.
        </p>
      </div>

      {targetsError && <p className="text-sm text-destructive">{targetsError.message}</p>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          label="AI/ML repos"
          value={aiTargets.length}
          hint="detected via dependency manifests (#185)"
          icon={Bot}
          unknown={targetsLoading}
        />
        <StatCard
          label="ModelScan findings"
          value={(modelscanFindings ?? []).length}
          hint="unsafe deserialization in serialized model files"
          icon={Boxes}
          tone={(modelscanFindings ?? []).length > 0 ? "attention" : "default"}
          unknown={modelscanLoading}
        />
        <StatCard
          label="LLM ruleset findings"
          value={(semgrepLlmFindings ?? []).length}
          hint="OWASP LLM Top 10 (unsafe eval/shell sinks, unpinned models)"
          icon={Radar}
          tone={(semgrepLlmFindings ?? []).length > 0 ? "attention" : "default"}
          unknown={semgrepLlmLoading}
        />
      </div>

      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">AI/ML-flagged repos</h2>

        {loading && <SkeletonList count={3} />}

        {!loading && aiTargets.length === 0 && (
          <EmptyState
            icon={Bot}
            title="No AI/ML repos detected yet"
            description="A target is flagged automatically when its dependency manifests reference AI/ML packages (PyTorch, transformers, langchain, and similar) -- or set manually from its Settings tab."
          />
        )}

        {!loading &&
          aiTargets.map((t) => {
            const modelscanCount = countFor("modelscan", t.id);
            const semgrepLlmCount = countFor("semgrep-llm", t.id);
            return (
              <Card key={t.id} className="border-border bg-card">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Link href={`/targets/${t.id}`} className="truncate font-medium text-foreground hover:underline">
                        {t.name}
                      </Link>
                      <Badge variant="outline" className="shrink-0 text-[10px]">
                        AI/ML
                      </Badge>
                    </div>
                    {t.is_ai_repo_signals && (
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">{t.is_ai_repo_signals}</p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2 text-xs">
                    <Link
                      href={`/findings?tool=modelscan&target_id=${t.id}`}
                      className={
                        modelscanCount > 0
                          ? "rounded border border-warning/30 bg-warning/10 px-2 py-1 text-warning hover:underline"
                          : "rounded border border-border px-2 py-1 text-muted-foreground hover:text-foreground hover:underline"
                      }
                    >
                      {modelscanCount} ModelScan
                    </Link>
                    <Link
                      href={`/findings?tool=semgrep-llm&target_id=${t.id}`}
                      className={
                        semgrepLlmCount > 0
                          ? "rounded border border-warning/30 bg-warning/10 px-2 py-1 text-warning hover:underline"
                          : "rounded border border-border px-2 py-1 text-muted-foreground hover:text-foreground hover:underline"
                      }
                    >
                      {semgrepLlmCount} LLM rules
                    </Link>
                  </div>
                </CardContent>
              </Card>
            );
          })}
      </div>

      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">AI Bill of Materials</h2>
        <Card className="border-border bg-card">
          <CardContent className="flex items-center justify-between gap-3 px-4 py-4">
            <p className="text-sm text-muted-foreground">
              Models and datasets a target depends on, extracted during SBOM generation. Pick a repo on the SBOM
              page and open its &quot;AI Bill of Materials&quot; tab.
            </p>
            <Link href="/sbom" className="shrink-0 text-xs text-accent-strong underline">
              Go to SBOM &amp; OSS Vulns
            </Link>
          </CardContent>
        </Card>
      </div>

      {/* Issue #191: garak needs a live model endpoint to probe rather than a
          repo checkout, so it never got a TOOL_COMMANDS entry -- it's
          catalog-only (visible in Tool Marketplace for install/health, not
          runnable). Rendering nothing here would silently claim LLM
          red-teaming exists; this says plainly that it doesn't yet. */}
      <div className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">LLM red-teaming</h2>
        <EmptyState
          icon={ShieldOff}
          title="Not yet available"
          description="garak (prompt injection, jailbreaks, data leakage probes) needs a live model endpoint to run against, not a repo checkout -- it's registered in the Tool Marketplace for visibility, but isn't wired into scanning yet."
        />
      </div>
    </div>
  );
}
