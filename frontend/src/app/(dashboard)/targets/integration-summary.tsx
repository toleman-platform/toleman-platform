"use client";

import { useState } from "react";
import { ChevronRight, Github } from "lucide-react";
import { ConnectGithubCard } from "@/components/features/integrations";

// Issue #125: the old page rendered ConnectGithubCard's full admin config
// (connect button, per-App installation list, webhook secret inputs) inline
// and above the fold on every visit, forcing daily users triaging the target
// inventory to scroll past integration plumbing first. Collapsed into a
// one-line summary strip by default; the full ConnectGithubCard (unchanged,
// reused verbatim; not re-implemented) only mounts once expanded, so its
// own status fetch/webhook-secret state doesn't run until someone actually
// opens it.
export function IntegrationSummary({
  installed,
  statusUnknown = false,
  accountLogin,
  targetsCount,
  defaultOpen,
}: {
  installed: boolean;
  /**
   * The status request failed, so `installed` is a fallback rather than an
   * answer. Without this the summary rendered "GitHub App not connected" off
   * a failed fetch -- a factual claim about the integration derived from not
   * knowing -- directly beneath a banner saying the state was unknown. The
   * page contradicted itself, and the more confident half was the wrong one.
   */
  statusUnknown?: boolean;
  accountLogin: string | null;
  targetsCount: number;
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);

  const summaryLabel = statusUnknown
    ? "GitHub App status unavailable · couldn't reach the API to check"
    : installed
      ? `GitHub App connected${accountLogin ? ` as ${accountLogin}` : ""} · ${targetsCount} repo${targetsCount === 1 ? "" : "s"} synced`
      : "GitHub App not connected · add targets manually or connect below";

  return (
    <div className="rounded-md border border-border bg-card">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left"
      >
        <span className="flex items-center gap-2 text-sm">
          <Github className="h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="text-foreground">{summaryLabel}</span>
        </span>
        <ChevronRight
          className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`}
        />
      </button>
      {open && (
        <div className="border-t border-border p-4">
          <ConnectGithubCard />
        </div>
      )}
    </div>
  );
}
