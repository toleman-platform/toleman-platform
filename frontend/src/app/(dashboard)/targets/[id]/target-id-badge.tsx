"use client";

import { useState } from "react";
import { Copy, Check } from "lucide-react";

// (#274) Snyk surfaces a project's ID directly on its detail page with a
// copy button, for API use. Ours was reachable -- it's in the URL
// (/targets/[id]) -- but not a labeled, one-click-copyable value on the
// page itself the way the workspace API key already has its own copy
// affordance (workspace-key-card.tsx). Someone scripting against
// GET /api/targets/{id} or building a public-API integration had to
// extract it from the URL bar rather than copy it directly.
export function TargetIdBadge({ targetId }: { targetId: number }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(String(targetId));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button
      type="button"
      onClick={copy}
      title="Copy target ID"
      aria-label={`Copy target ID ${targetId}`}
      className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground transition-colors hover:text-foreground"
    >
      ID {targetId}
      {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}
