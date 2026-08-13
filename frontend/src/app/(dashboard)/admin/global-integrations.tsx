"use client";

import { useEffect, useState } from "react";
import { api, AiProvider, PlatformConfigView } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { BrainCircuit, CheckCircle2 } from "lucide-react";
import { ConnectGithubCard } from "@/components/connect-github-card";

const PROVIDERS: { value: AiProvider; label: string }[] = [
  { value: "anthropic", label: "Anthropic (Claude)" },
  { value: "openai_compatible", label: "Custom OpenAI-compatible endpoint" },
];

export function GlobalIntegrations() {
  const [config, setConfig] = useState<PlatformConfigView | null>(null);
  const [provider, setProvider] = useState<AiProvider>("anthropic");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [compatKey, setCompatKey] = useState("");
  const [model, setModel] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function refresh() {
    api.getConfig().then((c) => {
      setConfig(c);
      setProvider(c.ai_provider);
      setBaseUrl(c.openai_compatible_base_url);
      setModel(c.openai_compatible_model);
    });
  }

  useEffect(refresh, []);

  async function save() {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const payload: Parameters<typeof api.updateConfig>[0] = { ai_provider: provider };
      if (provider === "anthropic") {
        if (apiKey.trim()) payload.anthropic_api_key = apiKey.trim();
      } else {
        payload.openai_compatible_base_url = baseUrl.trim();
        payload.openai_compatible_model = model.trim();
        if (compatKey.trim()) payload.openai_compatible_api_key = compatKey.trim();
      }
      await api.updateConfig(payload);
      setApiKey("");
      setCompatKey("");
      setSaved(true);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setSaving(false);
    }
  }

  const configuredNow =
    config &&
    (provider === "anthropic" ? config.anthropic_api_key_set : Boolean(config.openai_compatible_base_url && config.openai_compatible_model));

  const canSave = provider === "anthropic" ? true : baseUrl.trim().length > 0 && model.trim().length > 0;

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
              <div className="font-medium text-foreground">AI Provider</div>
              <div className="text-xs text-muted-foreground">Powers AI Analysis remediation suggestions</div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            {PROVIDERS.map((p) => (
              <label key={p.value} className="flex items-center gap-2 text-sm text-foreground">
                <input
                  type="radio"
                  name="ai_provider"
                  value={p.value}
                  checked={provider === p.value}
                  onChange={() => {
                    setProvider(p.value);
                    setSaved(false);
                  }}
                  className="h-4 w-4 accent-primary"
                />
                {p.label}
              </label>
            ))}
          </div>

          {configuredNow && (
            <div className="flex items-center gap-2 text-sm text-chart-5">
              <CheckCircle2 className="h-4 w-4" />
              Configured
            </div>
          )}

          {provider === "anthropic" && (
            <div className="flex gap-2">
              <Input
                type="password"
                className="bg-secondary"
                placeholder={config?.anthropic_api_key_set ? "Replace key..." : "sk-ant-..."}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </div>
          )}

          {provider === "openai_compatible" && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <Label htmlFor="oc-base-url" className="text-xs text-muted-foreground">
                  Base URL
                </Label>
                <Input
                  id="oc-base-url"
                  className="bg-secondary"
                  placeholder="http://localhost:11434/v1 (Ollama) or https://api.moonshot.cn/v1 (Kimi)"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="oc-api-key" className="text-xs text-muted-foreground">
                  API Key (optional -- self-hosted backends like Ollama usually don&apos;t need one)
                </Label>
                <Input
                  id="oc-api-key"
                  type="password"
                  className="bg-secondary"
                  placeholder={config?.openai_compatible_api_key_set ? "Replace key..." : "Leave blank if not required"}
                  value={compatKey}
                  onChange={(e) => setCompatKey(e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="oc-model" className="text-xs text-muted-foreground">
                  Model name
                </Label>
                <Input
                  id="oc-model"
                  className="bg-secondary"
                  placeholder="llama3.1, qwen2.5:0.5b, kimi-k2, ..."
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                />
              </div>
            </div>
          )}

          <Button onClick={save} disabled={saving || !canSave} className="self-start">
            {saving ? "Saving..." : "Save"}
          </Button>

          {saved && !error && <p className="text-xs text-chart-5">Saved.</p>}
          {error && <p className="text-xs text-destructive">{error}</p>}
          <p className="text-xs text-muted-foreground">
            Stored in the database (Admin-only). The Anthropic key takes precedence over ANTHROPIC_API_KEY in backend
            .env when that provider is selected.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
