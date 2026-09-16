"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Button } from "@/components/ui/button";

// (#247 follow-up) Per-package "Raise PR": the fix plan already knows the
// exact target version and which findings it resolves, so this needs no
// AI step and no diff-review dialog like the per-finding Suggest Fix flow
// -- one click opens the PR directly via POST .../remediations/raise-pr.
export function RemediationRaisePrButton({ targetId, packageName }: { targetId: number; packageName: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);

  async function raise() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.raisePackageFixPr(targetId, packageName);
      setPrUrl(res.pr_url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to raise PR");
    } finally {
      setBusy(false);
    }
  }

  if (prUrl) {
    return (
      <a
        href={safeHref(prUrl)}
        target="_blank"
        rel="noreferrer"
        className="text-xs text-accent-strong underline underline-offset-2"
      >
        View PR &rarr;
      </a>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button size="sm" variant="outline" onClick={raise} disabled={busy}>
        {busy ? "Raising PR..." : "Raise PR"}
      </Button>
      {error && <p className="text-right text-xs text-destructive">{error}</p>}
    </div>
  );
}
