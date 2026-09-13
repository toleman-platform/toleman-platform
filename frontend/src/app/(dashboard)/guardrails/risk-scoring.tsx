"use client";

import { useState } from "react";
import { api, ScoringWeight, ScoringWeights, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/features/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { Badge } from "@/components/ui/badge";
import { Building2, RotateCcw, SlidersHorizontal } from "lucide-react";

// Issue #201: weights for the fixed set of signal slots the risk-
// prioritisation engine scores on. Same workspace-picker-then-list shape as
// the SLA Rules tab (#70), and deliberately not a rules editor -- the
// backend has a closed catalogue of signals, so this surface is a row of
// dials, nothing more.
//
// The full catalogue comes from the server with the effective weight already
// merged in, so there is no copy of the shipped baseline in this file to
// drift out of sync with app/core/scoring.py.

const MAX_WEIGHT = 5;

// What a weight actually buys, in the slot's own terms. `contribution` comes
// from the server rather than being inferred from the signal id here,
// because the three kinds behave genuinely differently and describing one as
// another is how a tooltip becomes wrong:
//
//   multiplier  scales a factor of the base product; no points ceiling
//   points      adds up to max_points x weight
//   floor       raises the score *to* a level, so what it adds depends
//               entirely on where the finding already was -- KEV at weight
//               1.0 is worth 260 points to a finding sitting at 640 and 0
//               to one already above 900. "Up to 900 pts" was simply false.
function weightSummary(signal: ScoringWeight): string {
  if (signal.weight === 0) return "Off";
  if (signal.contribution === "multiplier" || signal.max_points === null) {
    return `${signal.weight}x`;
  }
  const scaled = Math.round(signal.max_points * signal.weight);
  if (signal.contribution === "floor") return `raises to a floor of ${scaled}`;
  return `up to ${scaled} pts`;
}

function SignalRow({
  signal,
  onSave,
  onReset,
  busy,
}: {
  signal: ScoringWeight;
  onSave: (weight: number) => void;
  onReset: () => void;
  busy: boolean;
}) {
  // Uncontrolled with a key so the input resets whenever the server hands
  // back a different value (a save, a reset, or a workspace switch) without
  // fighting the user mid-edit.
  return (
    <div className="flex flex-col gap-2 px-3 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground">{signal.label}</span>
          {signal.is_default ? (
            <Badge
              variant="outline"
              className="px-1.5 py-0 text-[10px] font-medium text-muted-foreground"
              title="No override saved for this workspace; the shipped baseline applies"
            >
              baseline
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="border-accent-strong/30 bg-accent px-1.5 py-0 text-[10px] font-medium text-accent-strong"
              title={`Overridden; the shipped baseline is ${signal.baseline_weight}`}
            >
              customised
            </Badge>
          )}
          <span className="text-[11px] text-muted-foreground">{weightSummary(signal)}</span>
        </div>
        <p className="mt-1 max-w-prose text-xs text-muted-foreground">{signal.description}</p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Input
          key={`${signal.signal}-${signal.weight}-${signal.workspace_id}`}
          type="number"
          min={0}
          max={MAX_WEIGHT}
          step={0.1}
          aria-label={`${signal.label} weight`}
          className="h-8 w-24 bg-secondary text-xs"
          defaultValue={signal.weight}
          disabled={busy}
          onBlur={(e) => {
            const raw = e.target.value.trim();
            if (raw === "") {
              // `Number("")` is 0, so selecting the field, deleting it and
              // tabbing away used to silently save "off" -- on the severity
              // slot that flattens every score in the workspace to the base
              // 40. An empty field is not a value; restore what is actually
              // configured and save nothing.
              e.target.value = String(signal.weight);
              return;
            }
            const next = Number(raw);
            if (!Number.isFinite(next) || next < 0 || next > MAX_WEIGHT) {
              // Out of range or not a number at all. The server rejects
              // these too (422); bouncing the input here means the user is
              // not told about a save they did not knowingly attempt.
              e.target.value = String(signal.weight);
              return;
            }
            if (next !== signal.weight) onSave(next);
          }}
        />
        <Button
          variant="ghost"
          size="icon"
          title={`Reset to the shipped baseline (${signal.baseline_weight})`}
          aria-label={`Reset ${signal.label} to baseline`}
          className="shrink-0 text-muted-foreground hover:text-foreground"
          disabled={signal.is_default || busy}
          onClick={onReset}
        >
          <RotateCcw className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

export function RiskScoring() {
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<ScoringWeights | null>(null);

  const {
    data: loaded,
    error: loadError,
    isInitialLoading: loading,
  } = useAsyncData<ScoringWeights>(() => api.scoringWeights(workspaceId!), {
    enabled: workspaceId != null,
    deps: [workspaceId],
  });

  // Every mutation returns the whole effective configuration, so the last
  // save is the freshest truth and there is no refetch round trip. Gated on
  // the workspace id so switching workspaces falls back to that workspace's
  // loaded config instead of briefly showing the previous one's weights.
  const config = saved && saved.workspace_id === workspaceId ? saved : loaded;

  const error = mutationError ?? loadError?.message ?? workspacesError?.message ?? null;

  async function mutate(run: () => Promise<ScoringWeights>) {
    setSaving(true);
    setMutationError(null);
    try {
      setSaved(await run());
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to save the scoring weight");
    } finally {
      setSaving(false);
    }
  }

  const anyCustomised = config?.signals.some((s) => !s.is_default) ?? false;

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <SlidersHorizontal className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Risk Scoring</div>
              <div className="text-xs text-muted-foreground">
                How much each signal counts toward a finding&apos;s priority score. Every weight is a
                multiplier on that signal&apos;s contribution: 1.0 is the shipped baseline, 0 switches the
                signal off. Nothing here can ever subtract from a score, so a signal the platform
                could not establish leaves a finding where it was rather than pushing it down the list.
              </div>
            </div>
          </div>

          {workspaces === null ? (
            <SkeletonList count={1} />
          ) : workspaces.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="No workspaces yet"
              description="Connect a target first to create a workspace."
              bare
            />
          ) : (
            <select
              className="w-fit rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={workspaceId ?? ""}
              onChange={(e) => setWorkspaceId(Number(e.target.value))}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {workspaceDisplayName(w, workspaces)}
                </option>
              ))}
            </select>
          )}

          {error && <p className="text-xs text-destructive">{error}</p>}

          {workspaceId != null && (
            <>
              {/* Priority scores are written during ingestion, so a weight
                  change reaches a finding only when a scan next observes it
                  (app/core/ingestion.py re-scores on every sighting). The
                  precise scope matters: a finding whose target is never
                  scanned again, or that has since been fixed, keeps the
                  score it was last given. Promising a blanket "next scan"
                  re-score would be false for exactly the findings someone
                  is most likely to check. */}
              <p className="text-xs text-muted-foreground">
                Weights apply when a scan scores a finding. Each finding is re-scored the next time a
                scan sees it still present, so a target that is not scanned again — or a finding
                already fixed or triaged away — keeps the score it last had. A finding&apos;s detail
                view always shows the breakdown against today&apos;s weights and flags when that
                differs from the stored score.
              </p>

              {loading || !config ? (
                <div className="px-3 py-2">
                  <SkeletonList count={4} />
                </div>
              ) : (
                <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                  {config.signals.map((signal) => (
                    <SignalRow
                      key={signal.signal}
                      signal={signal}
                      busy={saving}
                      onSave={(weight) =>
                        mutate(() =>
                          api.setScoringWeight({
                            workspace_id: workspaceId,
                            signal: signal.signal,
                            weight,
                          })
                        )
                      }
                      onReset={() => {
                        if (signal.rule_id !== null) {
                          const ruleId = signal.rule_id;
                          mutate(() => api.resetScoringWeight(ruleId));
                        }
                      }}
                    />
                  ))}
                </div>
              )}

              {config && !anyCustomised && (
                <p className="text-xs text-muted-foreground">
                  Nothing is customised in this workspace, so findings score exactly as they did
                  before scoring became configurable. CVSS exploitability, internet exposure and
                  fixability ship at 0 on purpose: switching one on changes how every finding in this
                  workspace ranks, which is a decision rather than an upgrade side effect.
                </p>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
