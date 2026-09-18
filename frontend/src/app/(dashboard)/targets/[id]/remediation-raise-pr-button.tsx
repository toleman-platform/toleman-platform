"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { pollUntilSettled } from "@/lib/poll";
import type { RemediationPrBatch } from "@/types";

// (#247 follow-up) Per-package "Raise PR": the fix plan already knows the
// exact target version and which findings it resolves, so this needs no
// AI step and no diff-review dialog like the per-finding Suggest Fix flow
// -- one click opens the PR directly via POST .../remediations/raise-pr.
//
// npm/yarn/pnpm packages are the one exception (#247 follow-up, real
// lockfile regeneration): the backend can't bump those inline -- it clones
// the repo and runs the real package manager
// (app.core.npm_lockfile_autofix), which can take up to ~3 minutes -- so
// it returns `batch_id` instead of `pr_url` and this button polls the same
// RemediationPrBatch job the bulk "Raise all" button already polls
// (RemediationBulkRaise), rather than getting a PR back directly.
export function RemediationRaisePrButton({ targetId, packageName }: { targetId: number; packageName: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [batchId, setBatchId] = useState<number | null>(null);

  useEffect(() => {
    if (batchId == null) return;
    const cancel = pollUntilSettled(
      () => api.getRaiseAllFixPrsBatch(batchId),
      (batch: RemediationPrBatch) => {
        if (batch.status === "running") return;
        const item = batch.items.find((i) => i.package === packageName) ?? batch.items[0];
        setBusy(false);
        setBatchId(null);
        if (item?.pr_url) {
          setPrUrl(item.pr_url);
        } else {
          setError(item?.error || "failed to raise PR");
        }
      },
      {
        onError: (err) => {
          setBusy(false);
          setBatchId(null);
          setError(err instanceof Error ? err.message : "failed to poll fix status");
        },
      },
    );
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batchId]);

  async function raise() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.raisePackageFixPr(targetId, packageName);
      if ("batch_id" in res) {
        setBatchId(res.batch_id);
        return;
      }
      setPrUrl(res.pr_url);
      setBusy(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to raise PR");
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
