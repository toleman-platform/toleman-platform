import Link from "next/link";
import { cn } from "@/lib/utils";

// Issue #197: sub-navigation for a target.
//
// Tab state lives in the URL rather than component state, deliberately. The
// Admin page keeps its tab in useState, which means none of its tabs are
// linkable -- you cannot send someone a link to Workspace Roles. A target's
// sub-pages get linked to constantly (from a finding, a PR comment, a Slack
// notification), so a plain `?tab=` query param is worth more here than the
// convenience of local state.
//
// Rendering them as <Link> also keeps the whole page a Server Component: no
// "use client" boundary, no client-side fetch waterfall, and each tab is a
// real navigation the browser can cache and the back button understands.
export const TARGET_TABS = [
  { id: "overview", label: "Overview" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "settings", label: "Settings" },
] as const;

export type TargetTab = (typeof TARGET_TABS)[number]["id"];

export function normalizeTab(raw: string | string[] | undefined): TargetTab {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return TARGET_TABS.some((t) => t.id === value) ? (value as TargetTab) : "overview";
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
