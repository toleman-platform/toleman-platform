"use client";

import { useState } from "react";
import { api, EnforcementMode, EnforcementModeSource } from "@/lib/api";
import { EnforcementModeLabel, EnforcementModeSelect } from "@/components/enforcement-mode-select";

// Issue #62: set this target's own PR Guardrail enforcement-mode override
// (Inherit/Block/Alert/Disabled) and show the effective resolved mode +
// where it came from (target/group/workspace/default), so enforcement is
// legible, not just settable. initialEffectiveMode/initialSource come from
// GET /api/targets/{id} (app.core.enforcement.resolve_enforcement_mode_with_source).
export function TargetEnforcement({
  targetId,
  initialMode,
  initialEffectiveMode,
  initialSource,
}: {
  targetId: number;
  initialMode: EnforcementMode | null;
  initialEffectiveMode: EnforcementMode;
  initialSource: EnforcementModeSource;
}) {
  const [mode, setMode] = useState<EnforcementMode | null>(initialMode);
  const [effectiveMode, setEffectiveMode] = useState<EnforcementMode>(initialEffectiveMode);
  const [source, setSource] = useState<EnforcementModeSource>(initialSource);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function change(next: EnforcementMode | null) {
    setBusy(true);
    setError(null);
    const prev = mode;
    setMode(next);
    try {
      await api.updateTarget(targetId, { enforcement_mode: next });
      const fresh = await api.target(targetId);
      setEffectiveMode(fresh.effective_enforcement_mode ?? "block");
      setSource(fresh.enforcement_mode_source ?? "default");
    } catch (e) {
      setMode(prev);
      setError(e instanceof Error ? e.message : "failed to update enforcement mode");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <span className="text-xs text-muted-foreground">PR Guardrail enforcement:</span>
      <EnforcementModeSelect value={mode} onChange={change} disabled={busy} />
      <EnforcementModeLabel mode={effectiveMode} source={source} />
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
