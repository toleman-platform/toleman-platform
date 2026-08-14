"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Users, Plug, Wrench, ShieldAlert, ClipboardCheck, KeyRound, Tag, Timer, GitBranch } from "lucide-react";
import { api, AuthUser } from "@/lib/api";
import { UserManagement } from "./user-management";
import { WorkspaceRoles } from "./workspace-roles";
import { GlobalIntegrations } from "./global-integrations";
import { ToolsHealth } from "./tools-health";
import { Policies } from "./policies";
import { ApprovalQueue } from "./approval-queue";
import { Groups } from "./groups";
import { SlaRules } from "./sla-rules";
import { WorkflowTemplates } from "./workflow-templates";

const TABS = [
  { id: "users", label: "User Management", icon: Users },
  { id: "workspace-roles", label: "Workspace Roles", icon: KeyRound },
  { id: "groups", label: "Repo Groups", icon: Tag },
  { id: "sla-rules", label: "SLA Rules", icon: Timer },
  { id: "workflow-templates", label: "Workflow Templates", icon: GitBranch },
  { id: "integrations", label: "Global Integrations", icon: Plug },
  { id: "tools", label: "Tools Health", icon: Wrench },
  { id: "policies", label: "Policies", icon: ShieldAlert },
  { id: "approval-queue", label: "Approval Queue", icon: ClipboardCheck },
] as const;

type TabId = (typeof TABS)[number]["id"];

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

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Admin</h1>
        <p className="text-sm text-muted-foreground">Users, integrations, and scanner health</p>
      </div>

      <div className="flex gap-1 border-b border-border">
        {visibleTabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "flex items-center gap-2 border-b-2 px-4 py-2 text-sm transition-colors",
              tab === t.id
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            )}
          >
            <t.icon className="h-4 w-4" />
            {t.label}
          </button>
        ))}
      </div>

      {tab === "users" && <UserManagement />}
      {tab === "workspace-roles" && <WorkspaceRoles />}
      {tab === "groups" && <Groups />}
      {tab === "sla-rules" && <SlaRules />}
      {tab === "workflow-templates" && <WorkflowTemplates />}
      {tab === "integrations" && <GlobalIntegrations />}
      {tab === "tools" && <ToolsHealth />}
      {tab === "policies" && <Policies />}
      {tab === "approval-queue" && canSeeApprovalQueue && <ApprovalQueue />}
    </div>
  );
}
