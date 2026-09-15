"use client";

import { useTabParam } from "@/hooks/use-tab-param";
import { cn } from "@/lib/utils";
import { Tag, Timer, GitBranch, ShieldCheck, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { PageHeader } from "@/components/ui/page-header";
import { HelpHint } from "@/components/ui/help-hint";
import { HELP_CONTENT } from "@/lib/help-content";
import { Groups } from "./groups";
import { SlaRules } from "./sla-rules";
import { WorkflowTemplates } from "./workflow-templates";
import { FpRules } from "./fp-rules";
import { Policies } from "./policies";
import { RiskScoring } from "./risk-scoring";

// IA review (#224): this is the old admin/page.tsx "Scan Config" group,
// promoted to its own top-level route. Same tabs, same components, same
// adminOnly sidebar visibility; only the URL and grouping changed.
const TABS = [
  { id: "groups", label: "Repo Groups", icon: Tag },
  { id: "sla-rules", label: "SLA Rules", icon: Timer },
  { id: "workflow-templates", label: "Workflow Templates", icon: GitBranch },
  { id: "fp-rules", label: "False Positive Rules", icon: ShieldCheck },
  { id: "policies", label: "Policies", icon: ShieldAlert },
  // (#201) Risk Scoring sits here rather than under Control Plane, matching
  // SLA Rules directly above it: same workspace-scoped shape, same
  // SECURITY_ENGINEER gate, same "security policy, not repo organisation"
  // reasoning. #224 moved scan-policy config out of Control Plane for
  // exactly this reason, and a scoring weight is as much a policy decision
  // as a days-to-fix window.
  { id: "risk-scoring", label: "Risk Scoring", icon: SlidersHorizontal },
] as const;

const TAB_IDS = TABS.map((t) => t.id);

export default function GuardrailsPage() {
  // (#235) Was useState; see use-tab-param.ts for why that made every
  // sub-page here unlinkable and reset on every visit.
  const [tab, setTab] = useTabParam(TAB_IDS, "groups");

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Guardrails"
        description="Repo groups, SLA rules, workflow templates, false-positive rules, policies, and risk scoring."
        badge={<HelpHint topic={HELP_CONTENT.guardrails} />}
      />

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
      {tab === "risk-scoring" && <RiskScoring />}
    </div>
  );
}
