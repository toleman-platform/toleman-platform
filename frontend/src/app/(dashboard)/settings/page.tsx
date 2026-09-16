"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Copy, UserCircle, Bell, Cog, type LucideIcon } from "lucide-react";
import {
  api,
  apiBaseUrl,
  type ApiToken,
  type ApiTokenScope,
  type AuthUser,
  type NotificationChannel,
  type NotificationEventType,
  type NotificationPreference,
  type Target,
} from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWriteAction } from "@/hooks/use-write-action";
import { useWorkspaceScopedSelection } from "@/hooks/use-workspace-scoped-selection";
import { useWorkspaceContext } from "@/contexts/workspace-context";
import { AsyncContent } from "@/components/ui/async-content";
import { AlertBanner } from "@/components/ui/alert-banner";
import { Card, CardContent } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/features/targets";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/ui/page-header";
import { cn } from "@/lib/utils";
import { Timestamp } from "@/components/ui/timestamp";

// mcp-server/README.md's own tool table, mirrored here so a user can see
// what a connected MCP client can actually do without leaving the app.
// Static: these are the tools mcp-server/server.py registers, not
// something the backend has any live inventory of to fetch.
const MCP_TOOLS: { name: string; scope: "read" | "read/write"; description: string }[] = [
  { name: "list_targets", scope: "read", description: "List targets in your accessible workspaces" },
  { name: "list_findings", scope: "read", description: "List findings, filterable by target/severity/state, paginated" },
  { name: "get_finding", scope: "read", description: "Full detail for one finding" },
  { name: "get_scan_status", scope: "read", description: "A scan's status/result" },
  { name: "trigger_scan", scope: "read/write", description: "Trigger a native scan against a target" },
  { name: "suggest_fix", scope: "read", description: "Fix recommendation (+ diff, where possible) for a finding; never writes anywhere" },
  { name: "raise_fix_pr", scope: "read/write", description: "Opens a PR for the exact patch a prior suggest_fix call returned" },
  { name: "check_code_for_vulnerabilities", scope: "read", description: "Scan a code snippet for vulnerabilities before it's written to a real file/commit" },
];

function McpServerCard() {
  const [copied, setCopied] = useState(false);
  // Issue #108: the remote (streamable-http) MCP server is deployed
  // alongside the public API at the same origin, under /mcp (see
  // mcp-server/README.md's "Remote (streamable-http)" section and
  // toleman-deploy's Caddyfile) -- so the same browser-facing API URL
  // every other public-API caller already uses is the right base for this
  // too, no separate env var to plumb through.
  const mcpUrl = `${apiBaseUrl()}/mcp`;

  function copy() {
    navigator.clipboard.writeText(mcpUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  const configSnippet = JSON.stringify(
    {
      mcpServers: {
        toleman: {
          url: mcpUrl,
          headers: { Authorization: "Bearer <your personal access token>" },
        },
      },
    },
    null,
    2
  );

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-3 px-4 py-4">
        <div>
          <h2 className="text-sm font-medium text-foreground">MCP Server</h2>
          <p className="text-xs text-muted-foreground">
            Connect Claude Code, Claude Desktop, or any other MCP-compatible tool directly to this Toleman
            instance -- list targets, browse findings, get a fix recommendation and open a PR for it, and check
            code for vulnerabilities while it&apos;s being written, not just after it&apos;s already committed.
            Authenticate with a personal access token from API Tokens below, passed as the connection&apos;s
            Bearer header.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <code className="flex-1 truncate rounded-md bg-secondary px-3 py-2 text-sm text-foreground">{mcpUrl}</code>
          <Button variant="outline" size="icon" aria-label="Copy MCP server URL" onClick={copy}>
            <Copy />
          </Button>
          {copied && <span className="shrink-0 text-xs text-chart-5">Copied</span>}
        </div>

        <details className="text-xs">
          <summary className="cursor-pointer text-foreground">Claude Code / Claude Desktop config</summary>
          <pre className="mt-2 overflow-x-auto rounded-md bg-secondary px-3 py-2 text-foreground">{configSnippet}</pre>
        </details>

        <details className="text-xs">
          <summary className="cursor-pointer text-foreground">Available tools</summary>
          <ul className="mt-2 flex flex-col gap-1.5">
            {MCP_TOOLS.map((t) => (
              <li key={t.name} className="text-muted-foreground">
                <code className="text-foreground">{t.name}</code>{" "}
                <span className="rounded bg-secondary px-1 py-0.5">{t.scope}</span> -- {t.description}
              </li>
            ))}
          </ul>
        </details>
      </CardContent>
    </Card>
  );
}

function ApiTokensCard() {
  // Was `api.apiTokens().then(setTokens)` with no `.catch`: a failed read left
  // `tokens` null forever, which this card rendered as a permanent
  // "Loading..." line. Routed through the hook/component pair that already
  // renders loading, error-with-retry and empty as three distinct things.
  const tokensState = useAsyncData<ApiToken[]>(() => api.apiTokens());
  const refresh = tokensState.refetch;
  const [name, setName] = useState("");
  const [scope, setScope] = useState<ApiTokenScope>("read");
  const [creating, setCreating] = useState(false);
  const [justCreated, setJustCreated] = useState<string | null>(null);
  const [copyFailed, setCopyFailed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Revoking is immediate and irreversible, and it breaks every CI pipeline
  // and MCP client presenting that token. It used to be one unguarded click
  // with no `try`/`catch`, so a failed revoke left the row reading as live
  // with nothing said at all.
  const [pendingRevoke, setPendingRevoke] = useState<ApiToken | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  async function create() {
    if (!name.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const created = await api.createApiToken(name.trim(), scope);
      setJustCreated(created.token);
      setCopyFailed(false);
      setName("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create token");
    } finally {
      setCreating(false);
    }
  }

  // `navigator.clipboard` is undefined on a non-secure origin -- plain http
  // over a LAN, which is a normal self-hosted deployment -- and the handler
  // threw. This is the only copy affordance for a value that is never shown
  // again, so a silent throw loses the token outright.
  async function copyJustCreated() {
    if (!justCreated) return;
    try {
      await navigator.clipboard.writeText(justCreated);
      setCopyFailed(false);
    } catch {
      setCopyFailed(true);
    }
  }

  async function confirmRevoke() {
    if (!pendingRevoke) return;
    setRevoking(true);
    setRevokeError(null);
    try {
      await api.revokeApiToken(pendingRevoke.id);
      setPendingRevoke(null);
      refresh();
    } catch (e) {
      // Dialog deliberately stays open: a closed dialog plus an unchanged row
      // is indistinguishable from "it worked".
      setRevokeError(e instanceof Error ? e.message : "failed to revoke token");
    } finally {
      setRevoking(false);
    }
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div>
          <h2 className="text-sm font-medium text-foreground">API Tokens</h2>
          <p className="text-xs text-muted-foreground">
            Personal access tokens for the public API (<code>/api/public/v1/*</code>, <code>Authorization: Bearer
            &lt;token&gt;</code>), separate from workspace API keys, which are CI-ingest-only. Default
            scope is read-only; request read/write to also trigger scans via the public API.
          </p>
        </div>

        {justCreated && (
          <div role="status" className="flex flex-col gap-2 rounded-md border border-chart-5/40 bg-chart-5/5 p-3">
            <p className="text-xs text-foreground">
              Copy this token now; it won&apos;t be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-md bg-secondary px-3 py-2 text-sm text-foreground">
                {justCreated}
              </code>
              <Button variant="outline" size="icon" aria-label="Copy token" onClick={copyJustCreated}>
                <Copy />
              </Button>
            </div>
            {copyFailed && (
              <p role="alert" className="text-xs text-destructive">
                Couldn&apos;t write to the clipboard (this browser blocks it outside a secure origin). Select the token
                above and copy it manually before dismissing this panel.
              </p>
            )}
            <Button variant="outline" size="sm" className="self-start" onClick={() => setJustCreated(null)}>
              Done
            </Button>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <Input
            className="h-9 min-w-[160px] flex-1 bg-secondary"
            placeholder="Token name (e.g. ci-pipeline)"
            aria-label="Token name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <select
            className="h-9 rounded-md border border-input bg-secondary px-3 text-sm text-foreground"
            aria-label="Token scope"
            value={scope}
            onChange={(e) => setScope(e.target.value as ApiTokenScope)}
          >
            <option value="read">Read-only</option>
            <option value="read_write">Read/write (can trigger scans and open PRs)</option>
          </select>
          <Button size="sm" disabled={creating || !name.trim()} onClick={create}>
            {creating ? "Creating…" : "Create token"}
          </Button>
        </div>
        {error && (
          <p role="alert" className="text-xs text-destructive">
            {error}
          </p>
        )}

        <div className="flex flex-col gap-2 border-t border-border pt-3">
          <AsyncContent
            state={tokensState}
            itemNoun="API tokens"
            errorTitle="Couldn't load your API tokens"
            emptyTitle="No API tokens yet"
            emptyDescription="Create one above to call the public API or connect an MCP client."
            skeletonCount={2}
          >
            {(tokens) => (
              <div className="flex flex-col gap-2">
                {tokens.map((t) => (
                  <div
                    key={t.id}
                    className="flex items-center justify-between gap-3 rounded-md border border-border bg-secondary/40 px-3 py-2"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium text-foreground">{t.name}</span>
                        <span className="shrink-0 rounded bg-secondary px-1.5 py-0.5 text-xs text-muted-foreground">
                          {t.scope === "read_write" ? "read/write" : "read-only"}
                        </span>
                        {t.revoked_at && (
                          <span className="shrink-0 rounded bg-destructive/10 px-1.5 py-0.5 text-xs text-destructive">
                            revoked
                          </span>
                        )}
                      </div>
                      <div className="mt-1 truncate text-xs text-muted-foreground">
                        {t.token_prefix}… · created <Timestamp value={t.created_at} mode="date" />
                        {t.last_used_at ? (
                          <>
                            {" · last used "}
                            <Timestamp value={t.last_used_at} mode="date" />
                          </>
                        ) : (
                          " · never used"
                        )}
                      </div>
                    </div>
                    {!t.revoked_at && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="shrink-0 text-destructive hover:text-destructive"
                        onClick={() => {
                          setRevokeError(null);
                          setPendingRevoke(t);
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </AsyncContent>
        </div>

        <ConfirmDialog
          open={pendingRevoke !== null}
          title={`Revoke "${pendingRevoke?.name ?? ""}"?`}
          description={
            <>
              Every CI pipeline and MCP client presenting this{" "}
              <strong>{pendingRevoke?.scope === "read_write" ? "read/write" : "read-only"}</strong> token starts
              failing <strong>immediately</strong>. Revoking can&apos;t be undone &mdash; you would have to create a new
              token and update each caller with it.
              {revokeError && <span className="mt-2 block text-destructive">{revokeError}</span>}
            </>
          }
          confirmLabel="Revoke token"
          tone="destructive"
          loading={revoking}
          onConfirm={confirmRevoke}
          onCancel={() => {
            setRevokeError(null);
            setPendingRevoke(null);
          }}
        />
      </CardContent>
    </Card>
  );
}

const LABELS = ["Prod", "Dev", "Internal", "Public"];

const NOTIFICATION_EVENT_TYPES: { value: NotificationEventType; label: string }[] = [
  { value: "critical_finding", label: "New Critical finding" },
  { value: "kev_cve", label: "KEV-listed CVE affecting our packages" },
  { value: "sla_breach", label: "A finding breaches its SLA" },
  { value: "scan_failure", label: "A scan fails" },
  { value: "malicious_package", label: "Malicious package detected" },
];
const NOTIFICATION_CHANNELS: { value: NotificationChannel; label: string }[] = [
  { value: "slack", label: "Slack" },
  { value: "email", label: "Email (preference saved; delivery not yet implemented)" },
];

function ProfileSection() {
  const [me, setMe] = useState<AuthUser | null>(null);
  const [name, setName] = useState("");
  const [nameSaved, setNameSaved] = useState(false);
  // Was `try`/`finally` with no `catch`: a rejected PATCH re-enabled the
  // button, left the typed name in the box and said nothing, so a rename the
  // server refused looked exactly like one it accepted. useWriteAction keeps
  // `submitting` and `error` in the same place, so the disabled state cannot
  // be wired up without the failure state coming with it.
  const nameAction = useWriteAction("Couldn't save your name");

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [pwSaving, setPwSaving] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwSaved, setPwSaved] = useState(false);

  useEffect(() => {
    api.me().then((u) => {
      setMe(u);
      setName(u.name);
    });
  }, []);

  async function saveName() {
    setNameSaved(false);
    await nameAction.run(async () => {
      const updated = await api.updateMe(name);
      setMe(updated);
      setNameSaved(true);
    });
  }

  async function changePassword() {
    setPwError(null);
    setPwSaved(false);
    if (newPassword !== confirmPassword) {
      setPwError("New password and confirmation don't match");
      return;
    }
    setPwSaving(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setPwSaved(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (e) {
      setPwError(e instanceof Error ? e.message : "failed to change password");
    } finally {
      setPwSaving(false);
    }
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-6 px-4 py-4">
        <div>
          <h2 className="text-sm font-medium text-foreground">Profile</h2>
          <p className="text-xs text-muted-foreground">{me?.email}</p>
        </div>

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">Name</label>
            <div className="flex gap-2">
              <Input className="bg-secondary" aria-label="Display name" value={name} onChange={(e) => setName(e.target.value)} />
              <Button onClick={saveName} disabled={nameAction.submitting} className="shrink-0">
                {nameAction.submitting ? "Saving..." : "Save"}
              </Button>
            </div>
            {nameSaved && <span role="status" className="text-xs text-chart-5">Saved</span>}
            {nameAction.error && (
              <AlertBanner tone="critical" title="Couldn't save your name">
                {nameAction.error}
              </AlertBanner>
            )}
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-border pt-4">
          <h3 className="text-xs font-medium text-foreground">Change Password</h3>
          {/* These three are the only fields in the app that genuinely *are*
              the user's login credential, so they get the real autoComplete
              tokens: the password manager can offer the stored password for
              the first and offer to save the new one for the other two. Every
              other password-typed field on these surfaces is a service secret
              and is marked autoComplete="off" instead, so a manager never
              offers to save a Slack webhook as a login or autofills the
              admin's own password into a Jira token box. */}
          <Input
            type="password"
            placeholder="Current password"
            aria-label="Current password"
            autoComplete="current-password"
            className="bg-secondary"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <Input
            type="password"
            placeholder="New password (min 8 characters)"
            aria-label="New password"
            autoComplete="new-password"
            className="bg-secondary"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <Input
            type="password"
            placeholder="Confirm new password"
            aria-label="Confirm new password"
            autoComplete="new-password"
            className="bg-secondary"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
          <div className="flex items-center gap-3">
            <Button
              onClick={changePassword}
              disabled={pwSaving || !currentPassword || !newPassword}
              className="self-start"
            >
              {pwSaving ? "Changing..." : "Change Password"}
            </Button>
            {pwSaved && <span role="status" className="text-xs text-chart-5">Password changed</span>}
          </div>
          {pwError && <p role="alert" className="text-xs text-destructive">{pwError}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

function NotificationPreferencesSection() {
  // Was `api.notificationPreferences().then(...)` with no `.catch`, and
  // `setLoading(false)` only on the success path: a rejected read left the
  // skeleton on screen for the rest of the session, with nothing to retry and
  // nothing saying the request had failed. Same hook/component pair the
  // sections beside this one already use, so loading, error-with-retry and
  // loaded are three distinguishable things.
  const prefsState = useAsyncData<NotificationPreference[]>(() => api.notificationPreferences());
  // The toggles the user has flipped since the read, keyed `channel:event`.
  // Kept beside the server's answer rather than copied over it in an effect:
  // copying would need a set-state-in-effect, and there would be a render in
  // which the two disagree.
  const [edits, setEdits] = useState<Map<string, boolean>>(new Map());
  const [saved, setSaved] = useState(false);
  const saveAction = useWriteAction("Couldn't save your notification preferences");

  const serverPrefs = useMemo(() => {
    const m = new Map<string, boolean>();
    for (const r of prefsState.data ?? []) m.set(`${r.channel}:${r.event_type}`, r.enabled);
    return m;
  }, [prefsState.data]);

  function enabledFor(channel: NotificationChannel, eventType: NotificationEventType): boolean {
    const key = `${channel}:${eventType}`;
    // `??`, not `||`: a deliberate `false` edit has to win over the server's
    // `true`, and `||` would fall through to it.
    return edits.get(key) ?? serverPrefs.get(key) ?? false;
  }

  function toggle(channel: NotificationChannel, eventType: NotificationEventType) {
    const key = `${channel}:${eventType}`;
    const next = !enabledFor(channel, eventType);
    setEdits((prev) => {
      const m = new Map(prev);
      m.set(key, next);
      return m;
    });
    setSaved(false);
  }

  async function save() {
    setSaved(false);
    await saveAction.run(async () => {
      const preferences: NotificationPreference[] = [];
      for (const channel of NOTIFICATION_CHANNELS) {
        for (const event of NOTIFICATION_EVENT_TYPES) {
          preferences.push({
            channel: channel.value,
            event_type: event.value,
            enabled: enabledFor(channel.value, event.value),
          });
        }
      }
      await api.setNotificationPreferences(preferences);
      setSaved(true);
    });
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div>
          <h2 className="text-sm font-medium text-foreground">Notification Preferences</h2>
          <p className="text-xs text-muted-foreground">
            Slack posts to the platform&apos;s configured webhook (Admin &gt; Global Integrations), naming opted-in
            users in the message.
          </p>
        </div>

        <AsyncContent
          state={prefsState}
          itemNoun="notification preferences"
          errorTitle="Couldn't load your notification preferences"
          // Nothing stored yet is not an empty state: every row below is a
          // choice the user can still make, defaulted off.
          isEmpty={() => false}
          loadingFallback={
            <div className="flex flex-col gap-3">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          }
        >
          {() => (
            <div className="flex flex-col gap-4">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs text-muted-foreground">
                      <th className="py-2 font-medium">Event</th>
                      {NOTIFICATION_CHANNELS.map((c) => (
                        <th key={c.value} className="py-2 pl-4 font-medium">
                          {c.label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {NOTIFICATION_EVENT_TYPES.map((event) => (
                      <tr key={event.value} className="border-b border-border/50">
                        <td className="py-2 text-foreground">{event.label}</td>
                        {NOTIFICATION_CHANNELS.map((channel) => (
                          <td key={channel.value} className="py-2 pl-4">
                            <input
                              type="checkbox"
                              aria-label={`${channel.label} for ${event.label}`}
                              className="h-4 w-4 accent-primary"
                              checked={enabledFor(channel.value, event.value)}
                              onChange={() => toggle(channel.value, event.value)}
                            />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Table and Save both live inside the loaded branch
                  deliberately. Every checkbox defaults to off, so a Save
                  offered beside a failed read would write "all notifications
                  disabled" from values nobody has ever seen. */}
              <div className="flex items-center gap-3">
                <Button onClick={save} disabled={saveAction.submitting} className="self-start">
                  {saveAction.submitting ? "Saving..." : "Save Preferences"}
                </Button>
                {saved && (
                  <span role="status" className="text-xs text-chart-5">
                    Saved
                  </span>
                )}
              </div>

              {saveAction.error && (
                <AlertBanner tone="critical" title="Couldn't save your notification preferences">
                  {saveAction.error}
                </AlertBanner>
              )}
            </div>
          )}
        </AsyncContent>
      </CardContent>
    </Card>
  );
}

function WorkspaceSection() {
  const { activeWorkspaceId } = useWorkspaceContext();
  // (#519) Resets on a workspace switch -- this picker has no "All
  // repositories" pseudo-value, so any selection is workspace-specific.
  const [chosenTargetIds, setChosenTargetIds] = useWorkspaceScopedSelection(activeWorkspaceId);
  // Was `try`/`finally` with no `catch`: a rejected PATCH said nothing at all
  // and left the rejection as an unhandled promise rejection escaping the
  // click handler. The draft itself was already preserved -- the clear sat
  // after the await, so a rejection never reached it -- so what was missing
  // was the failure being stated, not the edits being kept.
  const saveAction = useWriteAction("Couldn't save this target's configuration");
  // Both the draft and the "Saved" flag are tagged with the target they
  // belong to. Switching repos then falls back to that repo's stored values
  // automatically, where the previous effect-based reset could leave one
  // repo's unsaved edits (or a stale "Saved") sitting under another
  // repo's name for a frame.
  const [draft, setDraft] = useState<{ targetId: number; values: Partial<Target> } | null>(null);
  const [savedTargetId, setSavedTargetId] = useState<number | null>(null);

  // (#520) Workspace-scoped, same pattern as sbom/page.tsx: the global
  // workspace switcher narrows which repos this section can even see, and
  // the client-side filter covers the window where a switch's refetch is
  // still in flight and useAsyncData is still showing the previous
  // workspace's targets.
  const { data: targetsData, refetch: reloadTargets } = useAsyncData<Target[]>(
    () => api.targets({ workspace_id: activeWorkspaceId }),
    { deps: [activeWorkspaceId] },
  );
  const targets = (targetsData ?? []).filter(
    (t) => activeWorkspaceId === null || t.workspace_id === activeWorkspaceId,
  );
  // `??`, not a length check: `chosenTargetIds` is `null` only when nothing
  // has been explicitly chosen yet -- an explicit Clear in the picker sets
  // it to `[]`, which must stay `[]` here rather than silently snapping
  // back to the default (#519 review).
  const targetIds = chosenTargetIds ?? (targets[0] ? [targets[0].id] : []);
  const targetId = targetIds.length === 1 ? targetIds[0] : null;

  function chooseTargets(ids: number[]) {
    // A failure banner belongs to the target(s) it was raised on; carrying it
    // across a switch would accuse the next repo of a save it never ran.
    saveAction.clearError();
    bulkAction.clearError();
    setChosenTargetIds(ids);
  }

  const selectedTarget = targetId !== null ? (targets.find((t) => t.id === targetId) ?? null) : null;
  const form: Partial<Target> =
    draft && draft.targetId === targetId ? draft.values : (selectedTarget ?? {});
  const saved = savedTargetId !== null && savedTargetId === targetId;

  function setForm(update: (f: Partial<Target>) => Partial<Target>) {
    if (targetId === null) return;
    setDraft({ targetId, values: update(form) });
    setSavedTargetId(null);
  }

  async function save() {
    if (targetId === null) return;
    await saveAction.run(async () => {
      const updated = await api.updateTarget(targetId, {
        default_branch: form.default_branch,
        label: form.label,
        criticality_weight: form.criticality_weight,
      });
      reloadTargets();
      setDraft(null);
      setSavedTargetId(updated.id);
    });
  }

  // Bulk editing (#520): picking more than one repo switches from the
  // single-target editor above (whose default branch and label are
  // genuinely per-repo) to a narrower set of fields worth setting identically
  // across several repos at once -- label and criticality weight, not the
  // default branch, which bulk-setting would almost always get wrong for at
  // least one repo in the selection.
  const [bulkLabel, setBulkLabel] = useState<string>(LABELS[0]);
  const [bulkCriticality, setBulkCriticality] = useState(1);
  const [bulkApplyLabel, setBulkApplyLabel] = useState(false);
  const [bulkApplyCriticality, setBulkApplyCriticality] = useState(false);
  const [bulkResult, setBulkResult] = useState<{ succeeded: number; failed: number } | null>(null);
  const bulkAction = useWriteAction("Couldn't save the bulk update");

  async function saveBulk() {
    if (targetIds.length === 0 || (!bulkApplyLabel && !bulkApplyCriticality)) return;
    setBulkResult(null);
    await bulkAction.run(async () => {
      const patch: Partial<Target> = {};
      if (bulkApplyLabel) patch.label = bulkLabel;
      if (bulkApplyCriticality) patch.criticality_weight = bulkCriticality;
      const results = await Promise.allSettled(targetIds.map((id) => api.updateTarget(id, patch)));
      const succeeded = results.filter((r) => r.status === "fulfilled").length;
      const failed = results.length - succeeded;
      reloadTargets();
      setBulkResult({ succeeded, failed });
      if (failed > 0) {
        throw new Error(`${failed} of ${results.length} repositories failed to update.`);
      }
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="mb-3 text-sm font-medium text-foreground">Target Configuration</h2>
        <TargetPicker targets={targets} value={targetIds} onChange={chooseTargets} />
      </div>

      {targetIds.length > 1 && (
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col gap-4 px-4 py-4">
            <div>
              <h3 className="text-sm font-medium text-foreground">
                Bulk edit {targetIds.length} repositories
              </h3>
              <p className="text-xs text-muted-foreground">
                Only fields checked below are applied; the default branch is left alone since it&apos;s
                genuinely per-repo. Each repo is saved independently, so a failure on one doesn&apos;t
                block the rest.
              </p>
            </div>
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="bulk-apply-label"
                  className="h-4 w-4 accent-primary"
                  checked={bulkApplyLabel}
                  onChange={(e) => setBulkApplyLabel(e.target.checked)}
                />
                <label htmlFor="bulk-apply-label" className="w-32 text-xs text-muted-foreground">
                  Label
                </label>
                <select
                  className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground disabled:opacity-50"
                  value={bulkLabel}
                  disabled={!bulkApplyLabel}
                  onChange={(e) => setBulkLabel(e.target.value)}
                >
                  {LABELS.map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="bulk-apply-criticality"
                  className="h-4 w-4 accent-primary"
                  checked={bulkApplyCriticality}
                  onChange={(e) => setBulkApplyCriticality(e.target.checked)}
                />
                <label htmlFor="bulk-apply-criticality" className="w-32 text-xs text-muted-foreground">
                  Criticality weight (1-5)
                </label>
                <Input
                  type="number"
                  min={1}
                  max={5}
                  disabled={!bulkApplyCriticality}
                  className="w-24 bg-secondary"
                  value={bulkCriticality}
                  onChange={(e) => setBulkCriticality(Number(e.target.value))}
                />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button
                onClick={saveBulk}
                disabled={bulkAction.submitting || (!bulkApplyLabel && !bulkApplyCriticality)}
              >
                {bulkAction.submitting ? "Saving..." : `Apply to ${targetIds.length} repositories`}
              </Button>
              {bulkResult && bulkResult.failed === 0 && (
                <span role="status" className="text-xs text-chart-5">
                  Saved {bulkResult.succeeded} repositories
                </span>
              )}
            </div>
            {bulkAction.error && (
              <AlertBanner tone="critical" title="Couldn't save the bulk update">
                {bulkAction.error}
              </AlertBanner>
            )}
          </CardContent>
        </Card>
      )}

      {targetId !== null && (
        <Card className="border-border bg-card">
          <CardContent className="flex flex-col gap-4 px-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Default branch</label>
                <Input
                  className="bg-secondary"
                  value={form.default_branch ?? ""}
                  onChange={(e) => setForm((f) => ({ ...f, default_branch: e.target.value }))}
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Label</label>
                <select
                  className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                  value={form.label ?? "Dev"}
                  onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                >
                  {LABELS.map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Criticality weight (1-5)</label>
                {/* Shown as a bare number with no stated meaning, which an
                    external review flagged: nothing said how it enters the
                    risk score.

                    (#201) No longer restates the arithmetic. The formula is
                    weighted and workspace-configurable now, so "severity x
                    weight x 40" is only true on the shipped defaults and is
                    flatly wrong in a workspace that has retuned the
                    business-criticality slot. Describing the direction is
                    something that stays true; quoting the equation is a
                    promise this copy cannot keep. */}
                <p className="text-[11px] text-muted-foreground">
                  Multiplies this repo&apos;s risk scores, so its findings outrank identical ones on
                  less important repos. Raise it for production or internet-facing repos. How much it
                  counts for is configurable per workspace in Guardrails &rsaquo; Risk Scoring.
                </p>
                <Input
                  type="number"
                  min={1}
                  max={5}
                  className="bg-secondary"
                  value={form.criticality_weight ?? 1}
                  onChange={(e) => setForm((f) => ({ ...f, criticality_weight: Number(e.target.value) }))}
                />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button onClick={save} disabled={saveAction.submitting}>
                {saveAction.submitting ? "Saving..." : "Save Changes"}
              </Button>
              {saved && (
                <span role="status" className="text-xs text-chart-5">
                  Saved
                </span>
              )}
            </div>
            {saveAction.error && (
              <AlertBanner tone="critical" title="Couldn't save target configuration">
                {saveAction.error}
              </AlertBanner>
            )}
          </CardContent>
        </Card>
      )}

      <Card className="border-border bg-card">
        <CardContent className="flex items-center justify-between gap-3 px-4 py-4">
          <div>
            <p className="text-sm font-medium text-foreground">Workspace API key</p>
            <p className="text-xs text-muted-foreground">
              Moved to its own Workspaces page, manage it there alongside the workspace&apos;s name and roles.
            </p>
            {/* Two credential types for two different jobs, and an external
                review found nothing said which one a given integration wants. */}
            <p className="mt-1 text-[11px] text-muted-foreground">
              Use this one for CI pushing scan results in (<code>POST /api/ingest</code>). For the public API
              and the MCP server below, create a personal API token instead.
            </p>
          </div>
          <Link href="/workspaces" className="shrink-0 text-xs text-accent-strong underline">
            Go to Workspaces
          </Link>
        </CardContent>
      </Card>

      <McpServerCard />
      <ApiTokensCard />
    </div>
  );
}

// Issue #130: Settings was one long unsectioned scroll (Profile -> Password
// -> Notifications -> Target Configuration -> API key), inconsistent with
// Admin's grouped section-nav (#118) for a conceptually similar
// multi-section page. Reuses that exact pattern, a strip of pill buttons,
// `min-w-0 overflow-x-auto` so an overflowing strip scrolls within its own
// bounded container instead of pushing width overflow up onto `<main>`
// (see #118's admin/page.tsx for the full mechanism writeup); so the two
// pages stay visually and behaviorally consistent rather than inventing a
// second nav pattern.
const SECTIONS: { id: string; label: string; icon: LucideIcon }[] = [
  { id: "account", label: "Account", icon: UserCircle },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "workspace", label: "Workspace", icon: Cog },
];

type SectionId = (typeof SECTIONS)[number]["id"];

export default function SettingsPage() {
  const [section, setSection] = useState<SectionId>("account");
  const sectionsById = useMemo(() => new Map(SECTIONS.map((s) => [s.id, s])), []);
  const activeSection = sectionsById.get(section) ?? SECTIONS[0];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Settings"
        description="Profile, notifications, target configuration, and workspace credentials"
      />

      {/* Section-nav strip, same pattern as Admin's group-level nav (#118):
          a handful of pills, bounded within its own overflow-x-auto
          container so it never overflows the page width. */}
      <div className="min-w-0 overflow-x-auto border-b border-border">
        <div className="flex w-max min-w-full gap-1">
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              onClick={() => setSection(s.id)}
              className={cn(
                "flex shrink-0 items-center gap-2 border-b-2 px-4 py-2 text-sm transition-colors",
                activeSection.id === s.id
                  ? "border-accent-strong text-accent-strong"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              <s.icon className="h-4 w-4" />
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {section === "account" && <ProfileSection />}
      {section === "notifications" && <NotificationPreferencesSection />}
      {section === "workspace" && <WorkspaceSection />}
    </div>
  );
}
