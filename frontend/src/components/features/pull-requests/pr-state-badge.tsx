import * as React from "react";
import { GitMerge, GitPullRequest, GitPullRequestClosed, HelpCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { PullRequestState } from "@/types/github";

type PrStateConfig = { icon: React.ElementType; label: string; className: string };

/**
 * Colour follows DESIGN_SYSTEM.md "Status", which is workflow, not severity,
 * and explicitly not a rainbow: the steady state (open) is neutral, the
 * successful terminal state (merged) is positive (`chart-5`, the token
 * `ScanStatusBadge.completed` already uses), and the terminal state that
 * shipped nothing (closed) is muted. Open is neutral rather than the
 * "problem state" treatment DESIGN_SYSTEM.md gives an open *finding* -- an
 * unremediated vulnerability is a problem, a PR awaiting review is not.
 *
 * No entry animates. See PrStateBadge below for why that matters.
 */
const PR_STATE_CONFIG: Record<string, PrStateConfig> = {
  open: {
    icon: GitPullRequest,
    label: "Open",
    className: "border-border bg-secondary text-foreground",
  },
  merged: {
    icon: GitMerge,
    label: "Merged",
    className: "border-chart-5/30 bg-chart-5/10 text-chart-5",
  },
  closed: {
    icon: GitPullRequestClosed,
    label: "Closed",
    className: "border-border text-muted-foreground",
  },
};

// A state the API reports that this does not model. Rendering it as one of
// the three known states would be a confident claim about something never
// established (AGENTS.md #1.4), so it says only that the state is not known
// -- the same statement, and the same neutral treatment, as StatusBadge's
// "unknown" variant.
const UNRECOGNIZED_PR_STATE: PrStateConfig = {
  icon: HelpCircle,
  label: "Unknown",
  className: "border-border text-muted-foreground",
};

/**
 * A pull request's own lifecycle state: open, merged, closed.
 *
 * Deliberately its own small vocabulary rather than a reuse of the async-task
 * one (`StatusBadge`'s queued/running/completed/failed, and
 * `ScanStatusBadge`'s `ScanPhase`). Those describe work in flight; a pull
 * request's state does not. PR History used to route "open" through that
 * vocabulary as "running", whose rendering is a spinning loader, so every
 * open PR animated forever -- open is a steady state, and an animation that
 * never resolves also reads as a hung page.
 *
 * Nothing here animates, for that reason. A scan running *on* a PR is a
 * genuine phase and still renders through the scan status badge; only the
 * pull request's own state is rendered here.
 */
export function PrStateBadge({
  state,
  className,
}: {
  state: PullRequestState;
  className?: string;
}) {
  const config = PR_STATE_CONFIG[state] ?? UNRECOGNIZED_PR_STATE;
  const Icon = config.icon;

  return (
    <Badge
      variant="outline"
      className={cn("inline-flex items-center gap-1.5 font-medium", config.className, className)}
    >
      <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span>{config.label}</span>
    </Badge>
  );
}
