"use client";

import { useTabParam } from "@/hooks/use-tab-param";
import { cn } from "@/lib/utils";
import { Tag, Timer, GitBranch, ShieldCheck, ShieldAlert } from "lucide-react";
import { Groups } from "../admin/groups";
import { SlaRules } from "../admin/sla-rules";
import { WorkflowTemplates } from "../admin/workflow-templates";
import { FpRules } from "../admin/fp-rules";
import { Policies } from "../admin/policies";

// IA review (#224): this is the old admin/page.tsx "Scan Config" group,
// promoted to its own top-level route. Same tabs, same components, same
// adminOnly sidebar visibility -- only the URL and grouping changed.
const TABS = [
  { id: "groups", label: "Repo Groups", icon: Tag },
  { id: "sla-rules", label: "SLA Rules", icon: Timer },
  { id: "workflow-templates", label: "Workflow Templates", icon: GitBranch },
  { id: "fp-rules", label: "False Positive Rules", icon: ShieldCheck },
  { id: "policies", label: "Policies", icon: ShieldAlert },
] as const;

type TabId = (typeof TABS)[number]["id"];
const TAB_IDS = TABS.map((t) => t.id);

export default function GuardrailsPage() {
  // (#235) Was useState -- see use-tab-param.ts for why that made every
  // sub-page here unlinkable and reset on every visit.
  const [tab, setTab] = useTabParam(TAB_IDS, "groups");

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Guardrails</h1>
        <p className="text-sm text-muted-foreground">
          Repo groups, SLA rules, workflow templates, false-positive rules, and policies.
        </p>
      </div>

      <div className="min-w-0 overflow-x-auto border-b border-border">
        <div className="flex w-max min-w-full gap-1">
          {TABS.map((t) => (
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
          ))}
        </div>
      </div>

      {tab === "groups" && <Groups />}
      {tab === "sla-rules" && <SlaRules />}
      {tab === "workflow-templates" && <WorkflowTemplates />}
      {tab === "fp-rules" && <FpRules />}
      {tab === "policies" && <Policies />}
    </div>
  );
}
