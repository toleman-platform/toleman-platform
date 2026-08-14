"use client";

import { useEffect, useState } from "react";
import { api, AiProvider, PlatformConfigView } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { BrainCircuit, CheckCircle2, MessageSquare, Ticket } from "lucide-react";
import { ConnectGithubCard } from "@/components/connect-github-card";
import { SEVERITY_ORDER } from "@/lib/severity";

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

  // Slack (issue #74)
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");
  const [slackSaving, setSlackSaving] = useState(false);
  const [slackTesting, setSlackTesting] = useState(false);
  const [slackSaved, setSlackSaved] = useState(false);
  const [slackError, setSlackError] = useState<string | null>(null);
  const [slackTestResult, setSlackTestResult] = useState<string | null>(null);

  // Jira (issue #74)
  const [jiraUrl, setJiraUrl] = useState("");
  const [jiraApiToken, setJiraApiToken] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("");
  const [jiraIssueType, setJiraIssueType] = useState("Task");
  const [jiraAutoCreateSeverity, setJiraAutoCreateSeverity] = useState("");
  const [jiraSaving, setJiraSaving] = useState(false);
  const [jiraTesting, setJiraTesting] = useState(false);
  const [jiraSaved, setJiraSaved] = useState(false);
  const [jiraError, setJiraError] = useState<string | null>(null);
  const [jiraTestResult, setJiraTestResult] = useState<string | null>(null);

  function refresh() {
    api.getConfig().then((c) => {
      setConfig(c);
      setProvider(c.ai_provider);
      setBaseUrl(c.openai_compatible_base_url);
      setModel(c.openai_compatible_model);
      setJiraUrl(c.jira_url);
      setJiraProjectKey(c.jira_project_key);
      setJiraIssueType(c.jira_issue_type || "Task");
      setJiraAutoCreateSeverity(c.jira_auto_create_severity || "");
    });
  }

  useEffect(refresh, []);

  async function saveSlack() {
    setSlackSaving(true);
    setSlackError(null);
    setSlackSaved(false);
    setSlackTestResult(null);
    try {
      await api.updateConfig({ slack_webhook_url: slackWebhookUrl.trim() });
      setSlackWebhookUrl("");
      setSlackSaved(true);
      refresh();
    } catch (e) {
      setSlackError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setSlackSaving(false);
    }
  }

  async function testSlack() {
    setSlackTesting(true);
    setSlackError(null);
    setSlackTestResult(null);
    try {
      const result = await api.testSlack(slackWebhookUrl.trim() || undefined);
      setSlackTestResult(result.message || "Test message sent successfully.");
    } catch (e) {
      setSlackError(e instanceof Error ? e.message : "test connection failed");
    } finally {
      setSlackTesting(false);
    }
  }

  async function saveJira() {
    setJiraSaving(true);
    setJiraError(null);
    setJiraSaved(false);
    setJiraTestResult(null);
    try {
      const payload: Parameters<typeof api.updateConfig>[0] = {
        jira_url: jiraUrl.trim(),
        jira_project_key: jiraProjectKey.trim(),
        jira_issue_type: jiraIssueType.trim() || "Task",
        jira_auto_create_severity: jiraAutoCreateSeverity,
      };
      if (jiraApiToken.trim()) payload.jira_api_token = jiraApiToken.trim();
      await api.updateConfig(payload);
      setJiraApiToken("");
      setJiraSaved(true);
      refresh();
    } catch (e) {
      setJiraError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setJiraSaving(false);
    }
  }

  async function testJira() {
    setJiraTesting(true);
    setJiraError(null);
    setJiraTestResult(null);
    try {
      const result = await api.testJira(jiraUrl.trim() || undefined, jiraApiToken.trim() || undefined);
      setJiraTestResult(result.message || "Connected successfully.");
    } catch (e) {
      setJiraError(e instanceof Error ? e.message : "test connection failed");
    } finally {
      setJiraTesting(false);
    }
  }

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
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
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

      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <MessageSquare className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Slack</div>
              <div className="text-xs text-muted-foreground">Incoming webhook for notifications</div>
            </div>
          </div>

          {config?.slack_webhook_url_set && (
            <div className="flex items-center gap-2 text-sm text-chart-5">
              <CheckCircle2 className="h-4 w-4" />
              Configured
            </div>
          )}

          <div className="flex flex-col gap-1">
            <Label htmlFor="slack-webhook-url" className="text-xs text-muted-foreground">
              Webhook URL
            </Label>
            <Input
              id="slack-webhook-url"
              type="password"
              className="bg-secondary"
              placeholder={config?.slack_webhook_url_set ? "Replace webhook URL..." : "https://hooks.slack.com/services/..."}
              value={slackWebhookUrl}
              onChange={(e) => {
                setSlackWebhookUrl(e.target.value);
                setSlackSaved(false);
                setSlackTestResult(null);
              }}
            />
          </div>

          <div className="flex gap-2">
            <Button onClick={saveSlack} disabled={slackSaving || !slackWebhookUrl.trim()} className="self-start">
              {slackSaving ? "Saving..." : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={testSlack}
              disabled={slackTesting || (!slackWebhookUrl.trim() && !config?.slack_webhook_url_set)}
              className="self-start"
            >
              {slackTesting ? "Testing..." : "Test Connection"}
            </Button>
          </div>

          {slackSaved && !slackError && <p className="text-xs text-chart-5">Saved.</p>}
          {slackTestResult && !slackError && <p className="text-xs text-chart-5">{slackTestResult}</p>}
          {slackError && <p className="text-xs text-destructive">{slackError}</p>}
          <p className="text-xs text-muted-foreground">
            A real test message is posted to this webhook when you click Test Connection. Stored encrypted in the
            database (Admin-only).
          </p>
        </CardContent>
      </Card>

      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <Ticket className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Jira</div>
              <div className="text-xs text-muted-foreground">Auto-create tickets for findings</div>
            </div>
          </div>

          {config?.jira_url && config?.jira_api_token_set && (
            <div className="flex items-center gap-2 text-sm text-chart-5">
              <CheckCircle2 className="h-4 w-4" />
              Configured
            </div>
          )}

          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <Label htmlFor="jira-url" className="text-xs text-muted-foreground">
                Jira Server URL
              </Label>
              <Input
                id="jira-url"
                className="bg-secondary"
                placeholder="https://yourorg.atlassian.net"
                value={jiraUrl}
                onChange={(e) => {
                  setJiraUrl(e.target.value);
                  setJiraSaved(false);
                  setJiraTestResult(null);
                }}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="jira-api-token" className="text-xs text-muted-foreground">
                API Token
              </Label>
              <Input
                id="jira-api-token"
                type="password"
                className="bg-secondary"
                placeholder={config?.jira_api_token_set ? "Replace token..." : "API token or PAT"}
                value={jiraApiToken}
                onChange={(e) => {
                  setJiraApiToken(e.target.value);
                  setJiraSaved(false);
                  setJiraTestResult(null);
                }}
              />
            </div>
            <div className="flex gap-3">
              <div className="flex flex-1 flex-col gap-1">
                <Label htmlFor="jira-project-key" className="text-xs text-muted-foreground">
                  Project Key
                </Label>
                <Input
                  id="jira-project-key"
                  className="bg-secondary"
                  placeholder="SEC"
                  value={jiraProjectKey}
                  onChange={(e) => {
                    setJiraProjectKey(e.target.value);
                    setJiraSaved(false);
                  }}
                />
              </div>
              <div className="flex flex-1 flex-col gap-1">
                <Label htmlFor="jira-issue-type" className="text-xs text-muted-foreground">
                  Issue Type
                </Label>
                <Input
                  id="jira-issue-type"
                  className="bg-secondary"
                  placeholder="Task"
                  value={jiraIssueType}
                  onChange={(e) => {
                    setJiraIssueType(e.target.value);
                    setJiraSaved(false);
                  }}
                />
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="jira-auto-create-severity" className="text-xs text-muted-foreground">
                Auto-create ticket threshold
              </Label>
              <select
                id="jira-auto-create-severity"
                className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                value={jiraAutoCreateSeverity}
                onChange={(e) => {
                  setJiraAutoCreateSeverity(e.target.value);
                  setJiraSaved(false);
                }}
              >
                <option value="">Disabled</option>
                {SEVERITY_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {s} and above
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex gap-2">
            <Button onClick={saveJira} disabled={jiraSaving || !jiraUrl.trim() || !jiraProjectKey.trim()} className="self-start">
              {jiraSaving ? "Saving..." : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={testJira}
              disabled={jiraTesting || (!jiraUrl.trim() && !config?.jira_url) || (!jiraApiToken.trim() && !config?.jira_api_token_set)}
              className="self-start"
            >
              {jiraTesting ? "Testing..." : "Test Connection"}
            </Button>
          </div>

          {jiraSaved && !jiraError && <p className="text-xs text-chart-5">Saved.</p>}
          {jiraTestResult && !jiraError && <p className="text-xs text-chart-5">{jiraTestResult}</p>}
          {jiraError && <p className="text-xs text-destructive">{jiraError}</p>}
          <p className="text-xs text-muted-foreground">
            Test Connection makes a real authenticated call to your Jira instance. A ticket is auto-created for every
            new finding at or above the selected severity. API token stored encrypted in the database (Admin-only).
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
