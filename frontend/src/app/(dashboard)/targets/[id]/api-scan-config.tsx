"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";

// Issue #72: lets a developer set the live base URL of this target's
// deployed API. This is the ONLY source of a scan host for Active API
// Scanning (see Target.api_base_url's docstring in app/models/models.py) --
// deliberately requires an explicit save here rather than being inferred
// from repo_url, so a caller can never point an active scan at an
// arbitrary/unowned third-party URL.
export function ApiScanConfig({ targetId, initialApiBaseUrl }: { targetId: number; initialApiBaseUrl: string | null }) {
  const [value, setValue] = useState(initialApiBaseUrl ?? "");
  const [saved, setSaved] = useState(initialApiBaseUrl);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const trimmed = value.trim();
      const updated = await api.updateTarget(targetId, { api_base_url: trimmed || null });
      setSaved(updated.api_base_url);
      setValue(updated.api_base_url ?? "");
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save api_base_url");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={`api-base-url-${targetId}`} className="text-xs text-muted-foreground">
        Live API base URL (for Active API Scanning)
      </Label>
      <div className="flex items-center gap-2">
        <Input
          id={`api-base-url-${targetId}`}
          placeholder="https://api-staging.example.com"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={busy}
          className="max-w-md"
          aria-describedby={`api-base-url-${targetId}-hint`}
        />
        <Button size="sm" variant="outline" onClick={save} disabled={busy || value.trim() === (saved ?? "")}>
          {busy ? "Saving..." : "Save"}
        </Button>
      </div>
      <p id={`api-base-url-${targetId}-hint`} className="text-xs text-muted-foreground">
        Required before running an active scan -- discovered routes are combined with this host, never an
        arbitrary URL.
      </p>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
