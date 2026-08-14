"use client";

import { useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import {
  Users,
  Plug,
  Wrench,
  ShieldAlert,
  ClipboardCheck,
  KeyRound,
  Tag,
  Timer,
  GitBranch,
  ShieldCheck,
  Store,
  Lock,
  ScanSearch,
  type LucideIcon,
} from "lucide-react";
import { api, AuthUser } from "@/lib/api";
import { UserManagement } from "./user-management";
import { WorkspaceRoles } from "./workspace-roles";
import { GlobalIntegrations } from "./global-integrations";
import { ToolsHealth } from "./tools-health";
import { ToolMarketplace } from "./tool-marketplace";
import { Policies } from "./policies";
import { ApprovalQueue } from "./approval-queue";
import { Groups } from "./groups";
import { SlaRules } from "./sla-rules";
import { WorkflowTemplates } from "./workflow-templates";
import { FpRules } from "./fp-rules";

const TABS = [
  { id: "users", label: "User Management", icon: Users },
  { id: "workspace-roles", label: "Workspace Roles", icon: KeyRound },
  { id: "groups", label: "Repo Groups", icon: Tag },
  { id: "sla-rules", label: "SLA Rules", icon: Timer },
  { id: "workflow-templates", label: "Workflow Templates", icon: GitBranch },
  { id: "fp-rules", label: "False Positive Rules", icon: ShieldCheck },
  { id: "integrations", label: "Global Integrations", icon: Plug },
  { id: "tools", label: "Tools Health", icon: Wrench },
  { id: "tool-marketplace", label: "Tool Marketplace", icon: Store },
  { id: "policies", label: "Policies", icon: ShieldAlert },
  { id: "approval-queue", label: "Approval Queue", icon: ClipboardCheck },
] as const;

type TabId = (typeof TABS)[number]["id"];

// Issue #118: the 11 flat tabs above overflowed the tab strip (see the
// scroll-clip bug fixed below) and buried Approval Queue -- a
// security-review action likely checked daily -- at the very end. Grouping
// into 4 sections both fixes the overflow (each group's own strip is a
// handful of tabs, not 11) and promotes Approval Queue to its own
// one-item "Review" group instead of tab #11 of 11.
const GROUPS: { id: string; label: string; icon: LucideIcon; tabs: TabId[] }[] = [
  { id: "access", label: "Access", icon: Lock, tabs: ["users", "workspace-roles"] },
  { id: "scan-config", label: "Scan Config", icon: ScanSearch, tabs: ["groups", "sla-rules", "workflow-templates", "fp-rules", "policies"] },
  { id: "tooling", label: "Tooling", icon: Plug, tabs: ["integrations", "tools", "tool-marketplace"] },
  { id: "review", label: "Review", icon: ClipboardCheck, tabs: ["approval-queue"] },
];

// Approval Queue surfaces PR Guardrail ignore requests -- a security-team
// action (matches the backend's require_security_reviewer gate: admin or
// security_engineer, not any authenticated user reaching /admin).
const APPROVAL_QUEUE_ROLES = ["admin", "security_engineer"];

export default function AdminPage() {
  const [tab, setTab] = useState<TabId>("users");
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    api.me().then(setUser).catch(() => setUser(null));
  }, []);

  const canSeeApprovalQueue = !!user && APPROVAL_QUEUE_ROLES.includes(user.role);
  const visibleTabs = TABS.filter((t) => t.id !== "approval-queue" || canSeeApprovalQueue);
  const tabsById = useMemo(() => new Map(visibleTabs.map((t) => [t.id, t])), [visibleTabs]);
  const visibleGroups = useMemo(
    () =>
      GROUPS.map((g) => ({ ...g, tabs: g.tabs.filter((id) => tabsById.has(id)) })).filter(
        (g) => g.tabs.length > 0
      ),
    [tabsById]
  );

  const activeGroup = visibleGroups.find((g) => g.tabs.includes(tab)) ?? visibleGroups[0];

  function selectGroup(groupId: string) {
    const group = visibleGroups.find((g) => g.id === groupId);
    if (group && !group.tabs.includes(tab)) setTab(group.tabs[0]);
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Admin</h1>
        <p className="text-sm text-muted-foreground">Users, integrations, and scanner health</p>
      </div>

      <div className="flex flex-col gap-3">
        {/* Group-level nav (Access / Scan Config / Tooling / Review, #118) --
            a handful of pills, never enough to overflow, so no scroll
            container needed here. */}
        <div className="flex flex-wrap gap-2">
          {visibleGroups.map((g) => (
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

        {/* Sub-nav: the individual tabs within the active group. This strip
            is the thing that can overflow (e.g. Scan Config has 5 tabs) --
            `overflow-x-auto` scopes the horizontal scroll to *this* element.
            Bug fix (#118): the old flat 11-tab strip had no overflow
            handling at all, so an overflowing `flex` row silently expanded
            past its container's width. That pushed the width overflow up
            onto `<main>` (whose `overflow-y-auto` in the dashboard layout
            makes its computed overflow-x implicitly "auto" too, per the
            CSS overflow spec's visible+non-visible pairing rule), and
            clicking/focusing an off-screen tab button triggered the
            browser's default scroll-focused-element-into-view behavior on
            that nearest scrollable ancestor -- `<main>` itself -- shifting
            the *entire* page horizontally and clipping the sidebar (a flex
            sibling of `<main>`, now partly out of the shifted viewport) and
            truncating the header (scrolled left along with everything else
            inside `<main>`). Giving this div its own bounded scroll
            container (min-w-0 lets it shrink below its content's intrinsic
            width inside the flex-col parent, overflow-x-auto contains the
            scroll) means an off-screen tab button is already fully visible
            after *this* element scrolls, so the browser's scroll-into-view
            walk up the ancestor chain stops here and never reaches
            `<main>`. */}
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
      {tab === "workspace-roles" && <WorkspaceRoles />}
      {tab === "groups" && <Groups />}
      {tab === "sla-rules" && <SlaRules />}
      {tab === "workflow-templates" && <WorkflowTemplates />}
      {tab === "fp-rules" && <FpRules />}
      {tab === "integrations" && <GlobalIntegrations />}
      {tab === "tools" && <ToolsHealth />}
      {tab === "tool-marketplace" && <ToolMarketplace />}
      {tab === "policies" && <Policies />}
      {tab === "approval-queue" && canSeeApprovalQueue && <ApprovalQueue />}
    </div>
  );
}
