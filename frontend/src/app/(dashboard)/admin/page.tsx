"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import { Users, Plug, Wrench } from "lucide-react";
import { UserManagement } from "./user-management";
import { GlobalIntegrations } from "./global-integrations";
import { ToolsHealth } from "./tools-health";

const TABS = [
  { id: "users", label: "User Management", icon: Users },
  { id: "integrations", label: "Global Integrations", icon: Plug },
  { id: "tools", label: "Tools Health", icon: Wrench },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function AdminPage() {
  const [tab, setTab] = useState<TabId>("users");

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Admin</h1>
        <p className="text-sm text-muted-foreground">Users, integrations, and scanner health</p>
      </div>

      <div className="flex gap-1 border-b border-border">
        {TABS.map((t) => (
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
      {tab === "integrations" && <GlobalIntegrations />}
      {tab === "tools" && <ToolsHealth />}
    </div>
  );
}
