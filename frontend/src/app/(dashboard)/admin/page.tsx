"use client";

import { useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { Users, Plug, Wrench, Store, Lock, type LucideIcon } from "lucide-react";
import { UserManagement } from "./user-management";
import { GlobalIntegrations } from "./global-integrations";
import { ToolsHealth } from "./tools-health";
import { ToolMarketplace } from "./tool-marketplace";

const TABS = [
  { id: "users", label: "User Management", icon: Users },
  { id: "integrations", label: "Global Integrations", icon: Plug },
  { id: "tools", label: "Tools Health", icon: Wrench },
  { id: "tool-marketplace", label: "Tool Marketplace", icon: Store },
] as const;

type TabId = (typeof TABS)[number]["id"];

// IA review (#224): Control Plane keeps only what this app itself needs to
// run -- who can use it and what tools/integrations it talks to. Scan
// policy config moved to /guardrails, Approval Queue moved to its own
// /approval-queue route, and Workspace Roles moved into the new
// /workspaces page (which also absorbed the per-workspace API key that
// used to live in Settings behind a target picker).
const GROUPS: { id: string; label: string; icon: LucideIcon; tabs: TabId[] }[] = [
  { id: "access", label: "Access", icon: Lock, tabs: ["users"] },
  { id: "tooling", label: "Tooling", icon: Plug, tabs: ["integrations", "tools", "tool-marketplace"] },
];

export default function AdminPage() {
  const [tab, setTab] = useState<TabId>("users");

  const tabsById = useMemo(() => new Map(TABS.map((t) => [t.id, t])), []);
  const activeGroup = GROUPS.find((g) => g.tabs.includes(tab)) ?? GROUPS[0];

  function selectGroup(groupId: string) {
    const group = GROUPS.find((g) => g.id === groupId);
    if (group && !group.tabs.includes(tab)) setTab(group.tabs[0]);
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Control Plane</h1>
        <p className="text-sm text-muted-foreground">Users, integrations, and scanner health</p>
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          {GROUPS.map((g) => (
            <button
              key={g.id}
              onClick={() => selectGroup(g.id)}
              className={cn(
                "flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors",
                activeGroup?.id === g.id
                  ? "border-accent-strong/40 bg-accent text-accent-strong"
                  : "border-border bg-card text-muted-foreground hover:text-foreground"
              )}
            >
              <g.icon className="h-4 w-4" />
              {g.label}
            </button>
          ))}
        </div>

        {/* Bug fix #118 preserved: bounded scroll container so an
            off-screen tab's focus-scroll never escapes to <main>. Kept even
            though neither remaining group currently overflows two tabs --
            Tooling has 3 -- since a future tab addition regressing this is
            a one-line CSS omission that's easy to miss. */}
        <div className="min-w-0 overflow-x-auto border-b border-border">
          <div className="flex w-max min-w-full gap-1">
            {activeGroup?.tabs.map((tabId) => {
              const t = tabsById.get(tabId)!;
              return (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={cn(
                    "flex shrink-0 items-center gap-2 border-b-2 px-4 py-2 text-sm transition-colors",
                    tab === t.id
                      ? "border-accent-strong text-accent-strong"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                >
                  <t.icon className="h-4 w-4" />
                  {t.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {tab === "users" && <UserManagement />}
      {tab === "integrations" && <GlobalIntegrations />}
      {tab === "tools" && <ToolsHealth />}
      {tab === "tool-marketplace" && <ToolMarketplace />}
    </div>
  );
}
