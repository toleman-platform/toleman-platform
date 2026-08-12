"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { BrainCircuit, CheckCircle2 } from "lucide-react";
import { ConnectGithubCard } from "@/components/connect-github-card";

export function GlobalIntegrations() {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    api.getConfig().then((c) => setConfigured(c.anthropic_api_key_set));
  }

  useEffect(refresh, []);

  async function save() {
    if (!apiKey.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await api.updateConfig(apiKey.trim());
      setApiKey("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <ConnectGithubCard />

      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <BrainCircuit className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">AI Provider (Claude)</div>
              <div className="text-xs text-muted-foreground">Powers AI Analysis remediation suggestions</div>
            </div>
          </div>

          {configured && (
            <div className="flex items-center gap-2 text-sm text-chart-5">
              <CheckCircle2 className="h-4 w-4" />
              Configured
            </div>
          )}

          <div className="flex gap-2">
            <Input
              type="password"
              className="bg-secondary"
              placeholder={configured ? "Replace key..." : "sk-ant-..."}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            <Button onClick={save} disabled={saving || !apiKey.trim()} className="shrink-0">
              {saving ? "Saving..." : "Save"}
            </Button>
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
          <p className="text-xs text-muted-foreground">
            Stored in the database (Admin-only), takes precedence over ANTHROPIC_API_KEY in backend .env.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
