"use client";

import { useState } from "react";
import { api } from "@/lib/api";

// Issue #243: scan only the PR's changed files instead of the whole checkout.
//
// Deliberately worded as a trade rather than an optimisation. Turning this on
// is not free: a change in one file can make pre-existing code in another
// vulnerable, and a diff-scoped scan will not see it. An operator flipping
// this should understand they are narrowing what the PR gate checks, so the
// consequence is stated next to the switch rather than left to the docs --
// the same reasoning as the policy/enforcement note in TargetEnforcement.
export function TargetDiffScope({
  targetId,
  initialEnabled,
}: {
  targetId: number;
  initialEnabled: boolean;
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
      await api.updateTarget(targetId, { diff_scoped_pr_scans: next });
    } catch (e) {
      setEnabled(prev);
      setError(e instanceof Error ? e.message : "failed to update PR scan scope");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <label htmlFor="diff-scope" className="text-xs text-muted-foreground">
        PR scan scope:
      </label>
      <select
        id="diff-scope"
        className="h-8 rounded-md border border-input bg-background px-2 text-xs"
        value={enabled ? "diff" : "full"}
        disabled={busy}
        onChange={(e) => change(e.target.value === "diff")}
        aria-describedby="diff-scope-help"
      >
        <option value="full">Full repository</option>
        <option value="diff">Changed files only</option>
      </select>
      <span id="diff-scope-help" className="text-[11px] text-muted-foreground">
        {enabled
          ? "Faster, but pre-existing issues outside the diff are not checked. Every PR comment says so."
          : "Every PR scans the whole checkout."}
      </span>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
