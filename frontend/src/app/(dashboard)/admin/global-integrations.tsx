"use client";

import { useState } from "react";
import { api, AiProvider, GithubTokenView, PlatformConfigView, WorkspaceSummary, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { AsyncContent } from "@/components/ui/async-content";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SkeletonList } from "@/components/ui/skeleton";
import { AlertTriangle, BrainCircuit, CheckCircle2, Eye, EyeOff, Key, MessageSquare, Send, Ticket } from "lucide-react";
import { ConnectGithubCard } from "@/components/features/integrations";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Timestamp } from "@/components/ui/timestamp";

const PROVIDERS: { value: AiProvider; label: string }[] = [
  { value: "anthropic", label: "Anthropic (Claude)" },
  { value: "openai_compatible", label: "Custom OpenAI-compatible endpoint" },
];

// Issue #227: TTL presets for the per-workspace GitHub token. value is the
// TTL in hours; "" means never expire.
const GITHUB_TTL_OPTIONS: { value: string; label: string }[] = [
  { value: "", label: "Never" },
  { value: "24", label: "24 hours" },
  { value: "168", label: "7 days" },
  { value: "720", label: "30 days" },
  { value: "2160", label: "90 days" },
  { value: "8760", label: "1 year" },
];

// admin M13: every secret on this page was `type="password"` with no way
// back to plain text. That correctly stops a shoulder-surfer or a screen
// share from reading the value, but it also stops the admin who just pasted
// it from checking what they actually typed before hitting Save -- the only
// way to verify a masked paste was to already trust it, which is no
// verification at all. Defaulting to masked and putting the toggle under the
// admin's own explicit click (same shape as the sign-in field in
// app/login/page.tsx, and the workspace API-key card) keeps the credential
// off-screen by default while still letting them confirm it once, on
// purpose, immediately before it leaves the browser. autoComplete stays a
// hardcoded "off": every field this renders is a service secret, never the
// admin's own login, so a password manager must never offer to remember it
// as one (see settings/page.tsx's ProfileSection for the one place that
// distinction runs the other way).
function SecretInput({
  id,
  ariaLabel,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  ariaLabel: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  const [revealed, setRevealed] = useState(false);
  return (
    <div className="relative">
      <Input
        id={id}
        type={revealed ? "text" : "password"}
        autoComplete="off"
        spellCheck={false}
        className="bg-secondary pr-10"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        type="button"
        onClick={() => setRevealed((v) => !v)}
        aria-label={revealed ? `Hide ${ariaLabel}` : `Reveal ${ariaLabel}`}
        title={revealed ? `Hide ${ariaLabel}` : `Reveal ${ariaLabel}`}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
      >
        {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  );
}

/**
 * Fields the operator can edit that also have a stored server value. Absent =
 * untouched, so the rendered value falls through to `config`.
 */
type ConfigDraft = {
  provider?: AiProvider;
  baseUrl?: string;
  model?: string;
  jiraUrl?: string;
  jiraProjectKey?: string;
  jiraIssueType?: string;
  jiraAutoCreateSeverity?: string;
  siemExportSeverity?: string;
};

export function GlobalIntegrations() {
  // Issue: every read on this page used to be a bare `api.x().then(setX)`
  // with no `.catch`. A failed config read left `config` null, which this
  // component renders exactly like "nothing is configured" -- Slack, Jira,
  // SIEM, the AI key and the GitHub PAT all showing as unset on a platform
  // where they are all set. That is the worst possible lie on a secrets
  // page: it invites an admin to re-enter credentials that are already
  // stored. Both reads now go through `useAsyncData`, and the card stack
  // that depends on `config` is wrapped in `AsyncContent`, so a failed read
  // renders as a failure with a retry instead of as a clean empty form.
  const configState = useAsyncData<PlatformConfigView>(() => api.getConfig());
  const config = configState.data;

  // Editable fields are a *draft layered over server state*, not a copy of it
  // seeded by an effect. Copying meant "what the server holds" and "what the
  // operator typed" were the same variable, so there was no way to say which
  // provider is actually active while a radio sits unsaved -- and the seeding
  // effect was a setState-in-effect cascade besides. An absent key here means
  // "not edited; show what the server says".
  const [draft, setDraft] = useState<ConfigDraft>({});

  function edit<K extends keyof ConfigDraft>(key: K, value: ConfigDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  /** Drop the edits a successful save has just made the server's problem. */
  function commitDraft(...keys: (keyof ConfigDraft)[]) {
    setDraft((d) => {
      const next = { ...d };
      for (const k of keys) delete next[k];
      return next;
    });
  }

  const provider: AiProvider = draft.provider ?? config?.ai_provider ?? "anthropic";
  const baseUrl = draft.baseUrl ?? config?.openai_compatible_base_url ?? "";
  const model = draft.model ?? config?.openai_compatible_model ?? "";
  const jiraUrl = draft.jiraUrl ?? config?.jira_url ?? "";
  const jiraProjectKey = draft.jiraProjectKey ?? config?.jira_project_key ?? "";
  const jiraIssueType = draft.jiraIssueType ?? (config?.jira_issue_type || "Task");
  const jiraAutoCreateSeverity = draft.jiraAutoCreateSeverity ?? config?.jira_auto_create_severity ?? "";
  // `??` twice, never `||`: "" is the stored value for "auto-export disabled",
  // and coalescing that falsy value back to "High" showed the operator a
  // threshold the server was not holding. null (never configured) does fall
  // back to High.
  const siemExportSeverity = draft.siemExportSeverity ?? config?.siem_export_severity ?? "High";

  const [apiKey, setApiKey] = useState("");
  const [compatKey, setCompatKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);

  // Slack (issue #74)
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");
  const [slackSaving, setSlackSaving] = useState(false);
  const [slackTesting, setSlackTesting] = useState(false);
  const [slackSaved, setSlackSaved] = useState(false);
  const [slackError, setSlackError] = useState<string | null>(null);
  const [slackTestResult, setSlackTestResult] = useState<string | null>(null);

  // Jira (issue #74)
  const [jiraApiToken, setJiraApiToken] = useState("");
  const [jiraSaving, setJiraSaving] = useState(false);
  const [jiraTesting, setJiraTesting] = useState(false);
  const [jiraSaved, setJiraSaved] = useState(false);
  const [jiraError, setJiraError] = useState<string | null>(null);
  const [jiraTestResult, setJiraTestResult] = useState<string | null>(null);

  // SIEM Webhook
  const [siemWebhookUrl, setSiemWebhookUrl] = useState("");
  const [siemSaving, setSiemSaving] = useState(false);
  const [siemTesting, setSiemTesting] = useState(false);
  const [siemSaved, setSiemSaved] = useState(false);
  const [siemError, setSiemError] = useState<string | null>(null);
  const [siemTestResult, setSiemTestResult] = useState<string | null>(null);

  // Encryption key health banner
  const [reseedOpen, setReseedOpen] = useState(false);
  const [reseeding, setReseeding] = useState(false);
  const [reseedError, setReseedError] = useState<string | null>(null);

  // Workspace-scoped GitHub Personal Access Token (issue #74)
  const workspacesState = useAsyncData<WorkspaceSummary[]>(() => api.workspaces());
  const workspaces = workspacesState.data ?? [];
  const [githubWorkspaceChoice, setGithubWorkspaceChoice] = useState<number | null>(null);
  // Derived rather than defaulted from an effect: the card points at the first
  // workspace the moment the list lands, an explicit pick wins, and there is
  // no render where the id is stale relative to the list.
  const githubWorkspaceId = githubWorkspaceChoice ?? workspaces[0]?.id ?? null;
  const [githubToken, setGithubToken] = useState("");
  const [githubTtl, setGithubTtl] = useState("");
  const [githubSaving, setGithubSaving] = useState(false);
  const [githubTesting, setGithubTesting] = useState(false);
  const [githubDeleting, setGithubDeleting] = useState(false);
  const [githubRemoveOpen, setGithubRemoveOpen] = useState(false);
  const [githubSaved, setGithubSaved] = useState(false);
  const [githubError, setGithubError] = useState<string | null>(null);
  const [githubTestResult, setGithubTestResult] = useState<string | null>(null);

  // The PAT read used to be `.catch(() => {})`, which collapsed "the read
  // failed" into the same blank render as "no token stored". An unknown
  // token state must never present as "no token" -- see the three-way status
  // line below the card header.
  const githubTokenState = useAsyncData<GithubTokenView>(() => api.getGithubToken(githubWorkspaceId!), {
    enabled: githubWorkspaceId != null,
    deps: [githubWorkspaceId],
  });
  const githubTokenView = githubTokenState.data;
  const githubTokenUnknown = githubTokenState.isInitialLoading || (githubTokenState.status === "error" && githubTokenView === null);

  const refresh = configState.refetch;

  async function reseedEncryptionKey() {
    setReseeding(true);
    setReseedError(null);
    try {
      await api.reseedEncryptionKey();
      setReseedOpen(false);
      refresh();
    } catch (e) {
      // Previously uncaught: the dialog just sat open with no message, which
      // reads as "nothing happened" rather than "this failed".
      setReseedError(e instanceof Error ? e.message : "failed to reset the encryption-key warning");
    } finally {
      setReseeding(false);
    }
  }

  function selectGithubWorkspace(workspaceId: number) {
    setGithubWorkspaceChoice(workspaceId);
    setGithubError(null);
    setGithubTestResult(null);
    setGithubSaved(false);
  }

  async function saveGithubToken() {
    if (!githubToken.trim()) return;
    setGithubSaving(true);
    setGithubError(null);
    setGithubSaved(false);
    setGithubTestResult(null);
    try {
      await api.saveGithubToken(
        githubToken.trim(),
        githubTtl === "" ? null : Number(githubTtl),
        githubWorkspaceId ?? undefined
      );
      setGithubToken("");
      setGithubSaved(true);
      // Re-read rather than trusting the mutation's echo: the stored state is
      // the server's, and a refetch is the only thing that proves it.
      githubTokenState.refetch();
    } catch (e) {
      setGithubError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setGithubSaving(false);
    }
  }

  async function testGithubToken() {
    setGithubTesting(true);
    setGithubError(null);
    setGithubTestResult(null);
    try {
      const result = await api.testGithubToken(githubToken.trim() || undefined, githubWorkspaceId ?? undefined);
      setGithubTestResult(result.message || "Token is valid.");
    } catch (e) {
      setGithubError(e instanceof Error ? e.message : "test connection failed");
    } finally {
      setGithubTesting(false);
    }
  }

  async function removeGithubToken() {
    setGithubDeleting(true);
    setGithubError(null);
    setGithubTestResult(null);
    try {
      await api.deleteGithubToken(githubWorkspaceId ?? undefined);
      setGithubSaved(false);
      setGithubRemoveOpen(false);
      githubTokenState.refetch();
    } catch (e) {
      setGithubError(e instanceof Error ? e.message : "failed to remove");
      // Leave the dialog open on failure: closing it would read as "done".
    } finally {
      setGithubDeleting(false);
    }
  }

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
      commitDraft("jiraUrl", "jiraProjectKey", "jiraIssueType", "jiraAutoCreateSeverity");
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

  async function saveSiem() {
    setSiemSaving(true);
    setSiemError(null);
    setSiemSaved(false);
    setSiemTestResult(null);
    try {
      const payload: Parameters<typeof api.updateConfig>[0] = { siem_export_severity: siemExportSeverity };
      if (siemWebhookUrl.trim()) payload.siem_webhook_url = siemWebhookUrl.trim();
      await api.updateConfig(payload);
      setSiemWebhookUrl("");
      setSiemSaved(true);
      commitDraft("siemExportSeverity");
      refresh();
    } catch (e) {
      setSiemError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setSiemSaving(false);
    }
  }

  async function testSiem() {
    setSiemTesting(true);
    setSiemError(null);
    setSiemTestResult(null);
    try {
      const result = await api.testSiem(siemWebhookUrl.trim() || undefined);
      setSiemTestResult(result.message || "Test event sent successfully.");
    } catch (e) {
      setSiemError(e instanceof Error ? e.message : "test connection failed");
    } finally {
      setSiemTesting(false);
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
      commitDraft("provider", "baseUrl", "model");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save");
    } finally {
      setSaving(false);
    }
  }

  // Revoke the currently-stored key for whichever provider is selected --
  // clears it server-side (POST /api/config with "" -- see
  // UpdateConfigRequest's None-vs-"" convention) rather than just blanking
  // the local input, so AI Analysis and Autofix's AI-generated patches stop
  // working immediately, not just on this admin's next visit.
  async function revokeAiKey() {
    setRevoking(true);
    setError(null);
    setSaved(false);
    try {
      const payload: Parameters<typeof api.updateConfig>[0] =
        provider === "anthropic" ? { anthropic_api_key: "" } : { openai_compatible_api_key: "" };
      await api.updateConfig(payload);
      setApiKey("");
      setCompatKey("");
      setRevokeOpen(false);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to revoke key");
      // Dialog stays open so the failure is attached to the action that
      // caused it rather than appearing behind a dismissed modal.
    } finally {
      setRevoking(false);
    }
  }

  // "Configured" has to describe the *saved* provider, not whichever radio
  // happens to be selected. Deriving it from the local `provider` state meant
  // flipping the radio without saving repainted the green line to describe a
  // provider that was not the active one.
  const savedProvider: AiProvider = config?.ai_provider || "anthropic";
  const configuredNow =
    config &&
    (savedProvider === "anthropic"
      ? config.anthropic_api_key_set
      : Boolean(config.openai_compatible_base_url && config.openai_compatible_model));
  const savedProviderLabel = PROVIDERS.find((p) => p.value === savedProvider)?.label ?? savedProvider;
  const providerDirty = Boolean(config) && draft.provider !== undefined && draft.provider !== savedProvider;

  const canSave = provider === "anthropic" ? true : baseUrl.trim().length > 0 && model.trim().length > 0;

  return (
    <div className="flex flex-col gap-4">
      {config?.encryption_key_healthy === false && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
              <div>
                <div className="font-medium text-foreground">PLATFORM_ENCRYPTION_KEY mismatch detected</div>
                <div className="text-xs text-muted-foreground">
                  The configured encryption key can&apos;t decrypt secrets written by a previous key. GitHub App
                  credentials, Slack/Jira/SIEM webhooks, and the AI provider key below may all be undecryptable.
                  Reconnect each affected integration, then confirm below once everything works again.
                </div>
              </div>
            </div>
            <Button variant="destructive" className="shrink-0" onClick={() => setReseedOpen(true)}>
              I&apos;ve reconnected everything
            </Button>
          </CardContent>
        </Card>
      )}
      <ConfirmDialog
        open={reseedOpen}
        title="Confirm encryption key reset"
        description={
          <>
            Only confirm once every affected integration above has actually been reconnected. This clears the warning
            but does not itself fix any secret still encrypted under the old key.
            {reseedError && <span className="mt-2 block text-destructive">{reseedError}</span>}
          </>
        }
        confirmLabel="Confirm"
        tone="default"
        loading={reseeding}
        onConfirm={reseedEncryptionKey}
        onCancel={() => {
          setReseedError(null);
          setReseedOpen(false);
        }}
      />
      <ConnectGithubCard />

      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <Key className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">GitHub Token</div>
              <div className="text-xs text-muted-foreground">Clone private repos & enrich SBOM (per workspace)</div>
            </div>
          </div>

          {/* Three states, not two. "Checking" and "couldn't read" are both
              distinct from "no token stored": an admin who sees a blank card
              because the read failed will paste in a fresh PAT that the
              workspace already has. */}
          {githubTokenState.isInitialLoading ? (
            <div role="status" className="text-sm text-muted-foreground">
              Checking whether this workspace has a token stored&hellip;
            </div>
          ) : githubTokenState.status === "error" && githubTokenView === null ? (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
            >
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>
                Couldn&apos;t read this workspace&apos;s stored token ({githubTokenState.error?.message}). It may or
                may not be set &mdash; don&apos;t assume it isn&apos;t.
              </span>
              <Button size="sm" variant="outline" className="h-6 text-xs" onClick={githubTokenState.refetch}>
                Retry
              </Button>
            </div>
          ) : (
            githubTokenView?.token_set && (
              <div className="flex items-center gap-2 text-sm text-chart-5">
                <CheckCircle2 className="h-4 w-4" />
                {/* One span, not loose text plus a sibling <time>: in a flex
                    row each would become its own flex item and pick up the
                    container's gap mid-sentence. */}
                <span>
                  Configured
                  {githubTokenView.expires_at ? (
                    <>
                      {" · auto-purges "}
                      <Timestamp value={githubTokenView.expires_at} />
                    </>
                  ) : (
                    " · never expires"
                  )}
                </span>
              </div>
            )
          )}

          {workspacesState.isInitialLoading ? (
            <SkeletonList count={1} />
          ) : workspacesState.status === "error" && workspacesState.data === null ? (
            <p role="alert" className="text-xs text-destructive">
              Couldn&apos;t load the workspace list ({workspacesState.error?.message}). The token below can&apos;t be
              scoped to a workspace until it loads.{" "}
              <button type="button" className="underline" onClick={workspacesState.refetch}>
                Retry
              </button>
            </p>
          ) : (
            workspaces.length > 1 && (
              <div className="flex flex-col gap-1">
                <Label htmlFor="github-token-workspace" className="text-xs text-muted-foreground">
                  Workspace
                </Label>
                <select
                  id="github-token-workspace"
                  className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                  value={githubWorkspaceId ?? ""}
                  onChange={(e) => selectGithubWorkspace(Number(e.target.value))}
                >
                  {workspaces.map((w) => (
                    <option key={w.id} value={w.id}>
                      {workspaceDisplayName(w, workspaces)}
                    </option>
                  ))}
                </select>
              </div>
            )
          )}

          <div className="flex flex-col gap-1">
            <Label htmlFor="github-token" className="text-xs text-muted-foreground">
              Personal access token
            </Label>
            <SecretInput
              id="github-token"
              ariaLabel="GitHub token"
              placeholder={
                githubTokenUnknown
                  ? "Enter a token to replace whatever is stored…"
                  : githubTokenView?.token_set
                    ? "Replace token…"
                    : "ghp_… / github_pat_…"
              }
              value={githubToken}
              onChange={(v) => {
                setGithubToken(v);
                setGithubSaved(false);
                setGithubTestResult(null);
              }}
            />
          </div>

          <div className="flex flex-col gap-1">
            <Label htmlFor="github-token-ttl" className="text-xs text-muted-foreground">
              Auto-purge after
            </Label>
            <select
              id="github-token-ttl"
              className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
              value={githubTtl}
              onChange={(e) => {
                setGithubTtl(e.target.value);
                setGithubSaved(false);
              }}
            >
              {GITHUB_TTL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex gap-2">
            <Button onClick={saveGithubToken} disabled={githubSaving || !githubToken.trim()} className="self-start">
              {githubSaving ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={testGithubToken}
              disabled={githubTesting || (!githubToken.trim() && !githubTokenView?.token_set)}
              className="self-start"
            >
              {githubTesting ? "Testing…" : "Test Connection"}
            </Button>
            {githubTokenView?.token_set && (
              <Button
                variant="destructive"
                onClick={() => setGithubRemoveOpen(true)}
                disabled={githubDeleting}
                className="self-start"
              >
                {githubDeleting ? "Removing…" : "Remove"}
              </Button>
            )}
          </div>

          {/* The PAT is write-only by design, so removing it is unrecoverable:
              nobody can read the stored value back out to put it in again.
              Consequence-first copy, same shape as workspace-key-card.tsx's
              regenerate confirmation. */}
          <ConfirmDialog
            open={githubRemoveOpen}
            title="Remove this workspace's GitHub token?"
            description={
              <>
                Private-repo cloning and SBOM enrichment stop immediately for every target in{" "}
                <strong>
                  {workspaces.find((w) => w.id === githubWorkspaceId)
                    ? workspaceDisplayName(workspaces.find((w) => w.id === githubWorkspaceId)!, workspaces)
                    : "this workspace"}
                </strong>
                . The token is stored write-only and can&apos;t be read back, so it can&apos;t be restored &mdash;
                you&apos;d have to issue a new one on GitHub.
                {githubError && <span className="mt-2 block text-destructive">{githubError}</span>}
              </>
            }
            confirmLabel="Remove token"
            tone="destructive"
            loading={githubDeleting}
            onConfirm={removeGithubToken}
            onCancel={() => setGithubRemoveOpen(false)}
          />

          {githubSaved && !githubError && (
            <p role="status" className="text-xs text-chart-5">
              Saved.
            </p>
          )}
          {githubTestResult && !githubError && (
            <p role="status" className="text-xs text-chart-5">
              {githubTestResult}
            </p>
          )}
          {githubError && (
            <p role="alert" className="text-xs text-destructive">
              {githubError}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Use a fine-grained, repo-scoped PAT with <strong>Contents: Read-only</strong> permission (
            <strong>Metadata: Read-only</strong> is included automatically) &mdash; no other permissions are needed.
            Stored encrypted per workspace (Admin-only), never echoed back, and auto-purged once it expires. Test
            Connection makes a real authenticated call to GitHub.
          </p>
        </CardContent>
      </Card>

      {/* Everything below is rendered straight off `config`. If that read
          failed there is nothing honest to draw here: a blank Slack/Jira/SIEM
          form is indistinguishable from "these are not configured". AsyncContent
          gives the skeleton, the error-with-retry and the stale-data banner in
          one place, so a failed refresh keeps the last known state visible and
          says it is stale rather than silently reverting to "unset". */}
      <AsyncContent
        state={configState}
        itemNoun="integration settings"
        errorTitle="Couldn't load integration settings"
        loadingFallback={<SkeletonList count={4} />}
        className="flex flex-col gap-4"
      >
        {() => (
          <>
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
                        edit("provider", p.value);
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
                  Configured &middot; {savedProviderLabel}
                </div>
              )}

              {providerDirty && (
                <p role="status" className="text-xs text-muted-foreground">
                  Unsaved change: {savedProviderLabel} is still the active provider until you save.
                </p>
              )}

              {provider === "anthropic" && (
                <div className="flex flex-col gap-1">
                  <Label htmlFor="anthropic-api-key" className="text-xs text-muted-foreground">
                    Anthropic API key
                  </Label>
                  <SecretInput
                    id="anthropic-api-key"
                    ariaLabel="Anthropic API key"
                    placeholder={config?.anthropic_api_key_set ? "Replace key…" : "sk-ant-…"}
                    value={apiKey}
                    onChange={setApiKey}
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
                      onChange={(e) => edit("baseUrl", e.target.value)}
                    />
                  </div>
                  <div className="flex flex-col gap-1">
                    <Label htmlFor="oc-api-key" className="text-xs text-muted-foreground">
                      API Key (optional: self-hosted backends like Ollama usually don&apos;t need one)
                    </Label>
                    <SecretInput
                      id="oc-api-key"
                      ariaLabel="OpenAI-compatible API key"
                      placeholder={config?.openai_compatible_api_key_set ? "Replace key…" : "Leave blank if not required"}
                      value={compatKey}
                      onChange={setCompatKey}
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
                      onChange={(e) => edit("model", e.target.value)}
                    />
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                <Button onClick={save} disabled={saving || !canSave} className="self-start">
                  {saving ? "Saving…" : "Save"}
                </Button>
                {((provider === "anthropic" && config?.anthropic_api_key_set) ||
                  (provider === "openai_compatible" && config?.openai_compatible_api_key_set)) && (
                  <Button variant="destructive" onClick={() => setRevokeOpen(true)} disabled={revoking} className="self-start">
                    {revoking ? "Revoking…" : "Revoke key"}
                  </Button>
                )}
              </div>

              {/* The consequence used to live only in 12px muted helper text
                  below the button; it belongs at the point of no return. */}
              <ConfirmDialog
                open={revokeOpen}
                title="Revoke the stored AI provider key?"
                description={
                  <>
                    This clears the key server-side <strong>immediately</strong>. AI Analysis and Autofix&apos;s
                    AI-generated patches fall back to no-AI behavior for everyone on this platform until a new key is
                    saved. The stored key can&apos;t be read back, so revoking it means re-entering it from your
                    provider to undo this.
                    {error && <span className="mt-2 block text-destructive">{error}</span>}
                  </>
                }
                confirmLabel="Revoke key"
                tone="destructive"
                loading={revoking}
                onConfirm={revokeAiKey}
                onCancel={() => setRevokeOpen(false)}
              />

              {saved && !error && (
                <p role="status" className="text-xs text-chart-5">
                  Saved.
                </p>
              )}
              {error && (
                <p role="alert" className="text-xs text-destructive">
                  {error}
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                Stored in the database (Admin-only). The Anthropic key takes precedence over ANTHROPIC_API_KEY in backend
                .env when that provider is selected. Revoke key immediately clears the stored key -- AI Analysis and
                Autofix&apos;s AI-generated patches fall back to no-AI behavior until a new key is saved.
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
                <SecretInput
                  id="slack-webhook-url"
                  ariaLabel="Slack webhook URL"
                  placeholder={config?.slack_webhook_url_set ? "Replace webhook URL…" : "https://hooks.slack.com/services/..."}
                  value={slackWebhookUrl}
                  onChange={(v) => {
                    setSlackWebhookUrl(v);
                    setSlackSaved(false);
                    setSlackTestResult(null);
                  }}
                />
              </div>

              <div className="flex gap-2">
                <Button onClick={saveSlack} disabled={slackSaving || !slackWebhookUrl.trim()} className="self-start">
                  {slackSaving ? "Saving…" : "Save"}
                </Button>
                <Button
                  variant="outline"
                  onClick={testSlack}
                  disabled={slackTesting || (!slackWebhookUrl.trim() && !config?.slack_webhook_url_set)}
                  className="self-start"
                >
                  {slackTesting ? "Testing…" : "Test Connection"}
                </Button>
              </div>

              {slackSaved && !slackError && <p role="status" className="text-xs text-chart-5">Saved.</p>}
              {slackTestResult && !slackError && <p role="status" className="text-xs text-chart-5">{slackTestResult}</p>}
              {slackError && <p role="alert" className="text-xs text-destructive">{slackError}</p>}
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
                      edit("jiraUrl", e.target.value);
                      setJiraSaved(false);
                      setJiraTestResult(null);
                    }}
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="jira-api-token" className="text-xs text-muted-foreground">
                    API Token
                  </Label>
                  <SecretInput
                    id="jira-api-token"
                    ariaLabel="Jira API token"
                    placeholder={config?.jira_api_token_set ? "Replace token…" : "API token or PAT"}
                    value={jiraApiToken}
                    onChange={(v) => {
                      setJiraApiToken(v);
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
                        edit("jiraProjectKey", e.target.value);
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
                        edit("jiraIssueType", e.target.value);
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
                      edit("jiraAutoCreateSeverity", e.target.value);
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
                  {jiraSaving ? "Saving…" : "Save"}
                </Button>
                <Button
                  variant="outline"
                  onClick={testJira}
                  disabled={jiraTesting || (!jiraUrl.trim() && !config?.jira_url) || (!jiraApiToken.trim() && !config?.jira_api_token_set)}
                  className="self-start"
                >
                  {jiraTesting ? "Testing…" : "Test Connection"}
                </Button>
              </div>

              {jiraSaved && !jiraError && <p role="status" className="text-xs text-chart-5">Saved.</p>}
              {jiraTestResult && !jiraError && <p role="status" className="text-xs text-chart-5">{jiraTestResult}</p>}
              {jiraError && <p role="alert" className="text-xs text-destructive">{jiraError}</p>}
              <p className="text-xs text-muted-foreground">
                Test Connection makes a real authenticated call to your Jira instance. A ticket is auto-created for every
                new finding at or above the selected severity. API token stored encrypted in the database (Admin-only).
              </p>
            </CardContent>
          </Card>

          <Card className="border-border bg-card">
            <CardContent className="flex flex-col gap-4 px-4 py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
                  <Send className="h-5 w-5" />
                </div>
                <div>
                  <div className="font-medium text-foreground">SIEM Export</div>
                  <div className="text-xs text-muted-foreground">Generic webhook; one JSON event per qualifying finding</div>
                </div>
              </div>

              {config?.siem_webhook_url_set && (
                <div className="flex items-center gap-2 text-sm text-chart-5">
                  <CheckCircle2 className="h-4 w-4" />
                  Configured
                </div>
              )}

              <div className="flex flex-col gap-3">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="siem-webhook-url" className="text-xs text-muted-foreground">
                    Webhook URL
                  </Label>
                  <SecretInput
                    id="siem-webhook-url"
                    ariaLabel="SIEM webhook URL"
                    placeholder={config?.siem_webhook_url_set ? "Replace webhook URL…" : "https://your-siem.example.com/ingest"}
                    value={siemWebhookUrl}
                    onChange={(v) => {
                      setSiemWebhookUrl(v);
                      setSiemSaved(false);
                      setSiemTestResult(null);
                    }}
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="siem-export-severity" className="text-xs text-muted-foreground">
                    Auto-export threshold
                  </Label>
                  <select
                    id="siem-export-severity"
                    className="h-9 rounded-md border border-input bg-secondary px-2 text-sm text-foreground"
                    value={siemExportSeverity}
                    onChange={(e) => {
                      edit("siemExportSeverity", e.target.value);
                      setSiemSaved(false);
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
                <Button onClick={saveSiem} disabled={siemSaving} className="self-start">
                  {siemSaving ? "Saving…" : "Save"}
                </Button>
                <Button
                  variant="outline"
                  onClick={testSiem}
                  disabled={siemTesting || (!siemWebhookUrl.trim() && !config?.siem_webhook_url_set)}
                  className="self-start"
                >
                  {siemTesting ? "Testing…" : "Test Connection"}
                </Button>
              </div>

              {siemSaved && !siemError && <p role="status" className="text-xs text-chart-5">Saved.</p>}
              {siemTestResult && !siemError && <p role="status" className="text-xs text-chart-5">{siemTestResult}</p>}
              {siemError && <p role="alert" className="text-xs text-destructive">{siemError}</p>}
              <p className="text-xs text-muted-foreground">
                A real test event is posted to this webhook when you click Test Connection. A JSON event is sent for every
                new finding at or above the selected severity. Stored encrypted in the database (Admin-only).
              </p>
            </CardContent>
          </Card>
          </>
        )}
      </AsyncContent>
    </div>
  );
}
