import Link from "next/link";
import { cn } from "@/lib/utils";
import { QUEUES, type QueueId } from "@/lib/findings-view";

// Issue #197: sub-navigation for a target.
//
// Tab state lives in the URL rather than component state, deliberately. The
// Admin page keeps its tab in useState, which means none of its tabs are
// linkable; you cannot send someone a link to Workspace Roles. A target's
// sub-pages get linked to constantly (from a finding, a PR comment, a Slack
// notification), so a plain `?tab=` query param is worth more here than the
// convenience of local state.
//
// Rendering them as <Link> also keeps the whole page a Server Component: no
// "use client" boundary, no client-side fetch waterfall, and each tab is a
// real navigation the browser can cache and the back button understands.
export const TARGET_TABS = [
  { id: "overview", label: "Overview" },
  // (#247) Above Vulnerabilities deliberately: this answers "what do I do
  // about it", which only makes sense once "what is wrong" is in view, but
  // it is the higher-value question for a repo owner staring at a long
  // findings list, so it leads. GET /api/findings/remediations existed on
  // the backend, fully tested, with nothing on the frontend ever calling it.
  { id: "fix-plan", label: "Fix plan" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  // (#276) Dependencies answers "what is installed here", which the
  // findings list structurally cannot; it only ever shows what is
  // currently flagged. History answers "how has this changed", which the
  // overview's single "Last scan" timestamp cannot.
  { id: "dependencies", label: "Dependencies" },
  { id: "history", label: "History" },
  { id: "settings", label: "Settings" },
] as const;

export type TargetTab = (typeof TARGET_TABS)[number]["id"];

export function normalizeTab(raw: string | string[] | undefined): TargetTab {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return TARGET_TABS.some((t) => t.id === value) ? (value as TargetTab) : "overview";
}

/**
 * The findings queue the Vulnerabilities badge counts.
 *
 * "Needs action" is open findings with the licence category excluded, which
 * is what the word on the tab means: a copyleft obligation on a transitive
 * dependency is a policy question for one person once a quarter, not a
 * vulnerability. It is also the queue the tab opens on, so the badge and the
 * list underneath it report the same number.
 */
export const VULNERABILITY_TAB_QUEUE: QueueId = "action";

/**
 * Picks that queue's count out of the per-queue counts, which are indexed in
 * QUEUES order.
 *
 * `undefined` for a count that could not be fetched, which makes TargetTabs
 * drop the badge rather than claim zero for a target whose findings were
 * never counted.
 */
export function vulnerabilityTabCount(queueCounts: readonly (number | null)[]): number | undefined {
  return queueCounts[QUEUES.findIndex((q) => q.id === VULNERABILITY_TAB_QUEUE)] ?? undefined;
}

export function TargetTabs({
  targetId,
  active,
  vulnerabilityCount,
}: {
  targetId: number;
  active: TargetTab;
  vulnerabilityCount?: number;
}) {
  return (
    <div className="flex gap-1 border-b border-border">
      {TARGET_TABS.map((tab) => (
        <Link
          key={tab.id}
          href={`/targets/${targetId}?tab=${tab.id}`}
          scroll={false}
          aria-current={active === tab.id ? "page" : undefined}
          className={cn(
            "px-3 py-2 text-sm font-medium transition-colors",
            active === tab.id
              ? "border-b-2 border-primary text-foreground"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {tab.label}
          {tab.id === "vulnerabilities" && vulnerabilityCount !== undefined && ` (${vulnerabilityCount})`}
        </Link>
      ))}
    </div>
  );
}
