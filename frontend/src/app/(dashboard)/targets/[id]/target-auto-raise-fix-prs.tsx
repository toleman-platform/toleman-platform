"use client";

import { useState } from "react";
import { api } from "@/lib/api";

// (#247 follow-up) Let the platform push the Fix Plan's own dependency
// upgrades as real PRs unattended, on the periodic sweep, instead of
// requiring someone to click "Raise PR" per package.
//
// Same "state the consequence next to the switch" discipline as
// TargetDiffScope: turning this on lets the platform commit to and open
// PRs against the real repo with no review step before the PR itself, so
// that trade is spelled out inline rather than left to the docs.
//
// Rendered in two places (Settings, as the source of truth, and the Fix
// plan tab, next to "Raise all") -- one component, not a fork, so both
// stay in sync from the same optimistic-update logic.
export function TargetAutoRaiseFixPrs({
  targetId,
  initialEnabled,
  compact = false,
}: {
  targetId: number;
  initialEnabled: boolean;
  // Fix plan tab placement: a single inline control next to "Raise all"
  // rather than Settings' fuller label + help text.
  compact?: boolean;
}) {
  const [enabled, setEnabled] = useState(initialEnabled);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function change(next: boolean) {
    setBusy(true);
    setError(null);
    const prev = enabled;
    setEnabled(next);
    try {
      await api.updateTarget(targetId, { auto_raise_fix_prs: next });
    } catch (e) {
      setEnabled(prev);
      setError(e instanceof Error ? e.message : "failed to update auto-raise setting");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={compact ? "flex flex-wrap items-center gap-2" : "flex flex-wrap items-center gap-3"}>
      <label htmlFor={`auto-raise-fix-prs-${targetId}-${compact ? "compact" : "full"}`} className="text-xs text-muted-foreground">
        Auto-raise fix PRs:
      </label>
      <select
        id={`auto-raise-fix-prs-${targetId}-${compact ? "compact" : "full"}`}
        className="h-8 rounded-md border border-input bg-background px-2 text-xs"
        value={enabled ? "on" : "off"}
        disabled={busy}
        onChange={(e) => change(e.target.value === "on")}
        aria-describedby={`auto-raise-fix-prs-help-${targetId}-${compact ? "compact" : "full"}`}
      >
        <option value="off">Off</option>
        <option value="on">On</option>
      </select>
      {!compact && (
        <span id={`auto-raise-fix-prs-help-${targetId}-full`} className="text-[11px] text-muted-foreground">
          {enabled
            ? "New OSS/dependency fixes get a PR automatically, without review, on the next sweep."
            : "Fix Plan upgrades are only raised when someone clicks Raise PR."}
        </span>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
