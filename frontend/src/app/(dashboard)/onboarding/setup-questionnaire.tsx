"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Check, ShieldQuestion } from "lucide-react";
import { OnboardingChoices, OnboardingProfile, api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ErrorState } from "@/components/ui/error-state";
import { SkeletonList } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

// Issue #203: the first-run questionnaire. A fresh deployment used to enable
// every scanner regardless of what the operator runs -- gosec on an estate
// with no Go, Checkov with no Terraform, the AI ruleset on a shop shipping no
// models.
//
// Two rules shape this component:
//   1. Skippable at every step. A wizard that traps someone in a wrong
//      answer is worse than no wizard.
//   2. Nothing is switched off silently. The final step shows exactly which
//      scanners the answers turn off and why, *before* saving, and every one
//      is re-enabled in Admin -> Tool Marketplace afterwards.
type YesNo = boolean | null;

function ChoiceChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm transition-colors",
        active
          ? "border-primary bg-primary/10 text-foreground"
          : "border-input bg-secondary text-muted-foreground hover:text-foreground",
      )}
    >
      {active && <Check className="h-3.5 w-3.5 text-accent-strong" />}
      {children}
    </button>
  );
}

function YesNoRow({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  value: YesNo;
  onChange: (v: YesNo) => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="min-w-0">
        <div className="text-sm text-foreground">{label}</div>
        {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
      </div>
      <div className="flex gap-2">
        <ChoiceChip active={value === true} onClick={() => onChange(value === true ? null : true)}>
          Yes
        </ChoiceChip>
        <ChoiceChip active={value === false} onClick={() => onChange(value === false ? null : false)}>
          No
        </ChoiceChip>
      </div>
    </div>
  );
}

function Section({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        {description && <p className="text-xs text-muted-foreground">{description}</p>}
      </div>
      {children}
    </div>
  );
}

export function SetupQuestionnaire({ onDone }: { onDone?: () => void }) {
  const router = useRouter();
  const [choices, setChoices] = useState<OnboardingChoices | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<OnboardingProfile | null>(null);

  const [languages, setLanguages] = useState<string[]>([]);
  const [clouds, setClouds] = useState<string[]>([]);
  const [usesIac, setUsesIac] = useState<YesNo>(null);
  const [buildsAi, setBuildsAi] = useState<YesNo>(null);
  const [shipsContainers, setShipsContainers] = useState<YesNo>(null);
  const [prPreference, setPrPreference] = useState<string | null>(null);
  const [usesSlack, setUsesSlack] = useState<YesNo>(null);
  const [usesJira, setUsesJira] = useState<YesNo>(null);

  useEffect(() => {
    api
      .onboardingChoices()
      .then(setChoices)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load setup options"));
  }, []);

  function toggle(list: string[], setList: (v: string[]) => void, value: string) {
    setList(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);
  }

  async function save(skipped: boolean) {
    setSaving(true);
    setError(null);
    try {
      const saved = await api.saveOnboardingProfile({
        languages,
        cloud_providers: clouds,
        uses_iac: usesIac,
        builds_ai_features: buildsAi,
        ships_containers: shipsContainers,
        pr_enforcement_preference: prPreference,
        uses_slack: usesSlack,
        uses_jira: usesJira,
        skipped,
      });
      if (skipped) {
        onDone?.();
        router.refresh();
        return;
      }
      setResult(saved);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save setup answers");
    } finally {
      setSaving(false);
    }
  }

  if (error && !choices) return <ErrorState description={error} />;
  if (!choices) return <SkeletonList count={4} />;

  // Post-save summary. This is the screen that keeps the feature honest: it
  // names every scanner the answers switched off, and why, rather than
  // letting coverage quietly shrink.
  if (result) {
    const applied = result.applied ?? [];
    return (
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-6 py-6">
          <div className="flex items-center gap-2">
            <Check className="h-5 w-5 text-chart-5" />
            <h2 className="text-base font-semibold text-foreground">Setup saved</h2>
          </div>
          {applied.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Every scanner stays enabled. Nothing was switched off by your answers.
            </p>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                {applied.length} scanner{applied.length === 1 ? " was" : "s were"} switched off based on your
                answers. Each stays listed in Admin → Tool Marketplace and can be turned back on at any time.
              </p>
              <div className="flex flex-col gap-2">
                {applied.map((a) => (
                  <div key={a.tool} className="rounded-md border border-border bg-secondary/40 px-3 py-2">
                    <div className="font-mono text-xs text-foreground">{a.tool}</div>
                    <div className="text-xs text-muted-foreground">{a.reason}</div>
                  </div>
                ))}
              </div>
            </>
          )}
          <div className="flex gap-2">
            <Button
              size="sm"
              onClick={() => {
                onDone?.();
                router.refresh();
              }}
            >
              Continue
            </Button>
            <Button size="sm" variant="outline" onClick={() => router.push("/admin")}>
              Review in Tool Marketplace
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-6 px-6 py-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/10 text-accent-strong">
            <ShieldQuestion className="h-4 w-4" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-foreground">Tell us about your stack</h1>
            <p className="text-xs text-muted-foreground">
              Rikugan ships every scanner enabled. A few answers let it turn off the ones that cannot apply to
              you, so your findings are signal rather than noise. Every question is optional and everything
              here is editable later.
            </p>
          </div>
        </div>

        <Section
          title="Languages and ecosystems"
          description="Language-specific scanners stay off where they have nothing to analyse. Leave blank to keep them all on."
        >
          <div className="flex flex-wrap gap-2">
            {choices.languages.map((c) => (
              <ChoiceChip
                key={c.value}
                active={languages.includes(c.value)}
                onClick={() => toggle(languages, setLanguages, c.value)}
              >
                {c.label}
              </ChoiceChip>
            ))}
          </div>
        </Section>

        <Section title="Infrastructure and delivery">
          <div className="flex flex-col gap-3">
            <YesNoRow
              label="Do you manage infrastructure as code?"
              hint="Terraform, Kubernetes manifests, CloudFormation — drives Checkov and tfsec."
              value={usesIac}
              onChange={setUsesIac}
            />
            <YesNoRow
              label="Do you build and ship container images?"
              hint="Drives container image scanning alongside filesystem scanning."
              value={shipsContainers}
              onChange={setShipsContainers}
            />
            <YesNoRow
              label="Do you build AI or ML features?"
              hint="Drives model-file scanning and the LLM ruleset. Repositories are checked for AI content on every scan regardless, so this is only a default."
              value={buildsAi}
              onChange={setBuildsAi}
            />
          </div>
        </Section>

        <Section title="Cloud providers" description="Recorded for future infrastructure rule tuning.">
          <div className="flex flex-wrap gap-2">
            {choices.cloud_providers.map((c) => (
              <ChoiceChip
                key={c.value}
                active={clouds.includes(c.value)}
                onClick={() => toggle(clouds, setClouds, c.value)}
              >
                {c.label}
              </ChoiceChip>
            ))}
          </div>
        </Section>

        <Section
          title="Pull request policy"
          description="What should happen when a pull request introduces a new finding?"
        >
          <div className="flex flex-wrap gap-2">
            {choices.pr_enforcement.map((c) => (
              <ChoiceChip
                key={c.value}
                active={prPreference === c.value}
                onClick={() => setPrPreference(prPreference === c.value ? null : c.value)}
              >
                {c.label}
              </ChoiceChip>
            ))}
          </div>
        </Section>

        <Section title="Where should alerts go?" description="We will point you at the integration, not configure it for you.">
          <div className="flex flex-col gap-3">
            <YesNoRow label="Do you use Slack?" value={usesSlack} onChange={setUsesSlack} />
            <YesNoRow label="Do you use Jira?" value={usesJira} onChange={setUsesJira} />
          </div>
        </Section>

        {error && <p className="text-sm text-destructive">{error}</p>}

        <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4">
          <Button size="sm" disabled={saving} onClick={() => save(false)}>
            {saving ? "Saving..." : "Save and continue"}
          </Button>
          <Button size="sm" variant="outline" disabled={saving} onClick={() => save(true)}>
            Skip for now
          </Button>
          <span className="text-xs text-muted-foreground">
            Skipping keeps every scanner enabled — the current behaviour.
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
