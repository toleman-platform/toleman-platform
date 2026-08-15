"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Copy, Eye, EyeOff, RotateCw, UserCircle, Bell, Cog, type LucideIcon } from "lucide-react";
import {
  api,
  ApiToken,
  ApiTokenScope,
  AuthUser,
  NotificationChannel,
  NotificationEventType,
  NotificationPreference,
  Target,
} from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

const MASKED_KEY = "•".repeat(32);

function WorkspaceKeyCard({ targetId }: { targetId: number }) {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Remounted with `key={targetId}` by the parent on target switch, so
  // per-target UI state (revealed/copied/confirming/error) resets for free
  // without needing setState calls here for anything but the fetched key.
  useEffect(() => {
    api.workspaceKey(targetId).then((r) => setApiKey(r.api_key));
  }, [targetId]);

  async function copyKey() {
    if (!apiKey) return;
    await navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function regenerate() {
    setRegenerating(true);
    setError(null);
    try {
      const r = await api.regenerateWorkspaceKey(targetId);
      setApiKey(r.api_key);
      setRevealed(true);
      setConfirming(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to regenerate key");
    } finally {
      setRegenerating(false);
    }
  }

  if (!apiKey) return null;

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-3 px-4 py-4">
        <div>
          <p className="text-xs text-muted-foreground">Workspace API key (for CI push ingestion, X-API-Key header)</p>
          <p className="text-xs text-muted-foreground">
            This key authenticates automated pipeline pushes to this workspace. Anyone holding it can push findings
            on your behalf.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <code className="flex-1 break-all rounded-md bg-secondary px-3 py-2 text-sm text-foreground">
            {revealed ? apiKey : MASKED_KEY}
          </code>
          <Button
            variant="outline"
            size="icon"
            aria-label={revealed ? "Hide API key" : "Reveal API key"}
            title={revealed ? "Hide API key" : "Reveal API key"}
            onClick={() => setRevealed((v) => !v)}
          >
            {revealed ? <EyeOff /> : <Eye />}
          </Button>
          <Button variant="outline" size="icon" aria-label="Copy API key" title="Copy API key" onClick={copyKey}>
            <Copy />
          </Button>
        </div>
        {copied && <span className="text-xs text-chart-5">Copied to clipboard</span>}

        <div className="flex flex-col gap-2 border-t border-border pt-3">
          {!confirming ? (
            <Button
              variant="outline"
              size="sm"
              className="self-start text-destructive hover:text-destructive"
              onClick={() => setConfirming(true)}
            >
              <RotateCw />
              Regenerate key
            </Button>
          ) : (
            <div className="flex flex-col gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3">
              <p className="text-xs text-foreground">
                Regenerating invalidates the current key <strong>immediately</strong>. Any CI pipeline still using it
                will start failing to push findings until it&apos;s updated with the new key. This can&apos;t be
                undone.
              </p>
              <div className="flex items-center gap-2">
                <Button variant="destructive" size="sm" disabled={regenerating} onClick={regenerate}>
                  {regenerating ? "Regenerating..." : "Yes, regenerate now"}
                </Button>
                <Button variant="outline" size="sm" disabled={regenerating} onClick={() => setConfirming(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

function ApiTokensCard() {
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [name, setName] = useState("");
  const [scope, setScope] = useState<ApiTokenScope>("read");
  const [creating, setCreating] = useState(false);
  const [justCreated, setJustCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    api.apiTokens().then(setTokens);
  }

  useEffect(refresh, []);

  async function create() {
    if (!name.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const created = await api.createApiToken(name.trim(), scope);
      setJustCreated(created.token);
      setName("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to create token");
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: number) {
    await api.revokeApiToken(id);
    refresh();
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-4 px-4 py-4">
        <div>
          <h2 className="text-sm font-medium text-foreground">API Tokens</h2>
          <p className="text-xs text-muted-foreground">
            Personal access tokens for the public API (<code>/api/public/v1/*</code>, <code>Authorization: Bearer
            &lt;token&gt;</code>) -- separate from the workspace API key above, which is CI-ingest-only. Default
            scope is read-only; request read/write to also trigger scans via the public API.
          </p>
        </div>

        {justCreated && (
          <div className="flex flex-col gap-2 rounded-md border border-chart-5/40 bg-chart-5/5 p-3">
            <p className="text-xs text-foreground">
              Copy this token now -- it won&apos;t be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-md bg-secondary px-3 py-2 text-sm text-foreground">
                {justCreated}
              </code>
              <Button
                variant="outline"
                size="icon"
                aria-label="Copy token"
                onClick={() => navigator.clipboard.writeText(justCreated)}
              >
                <Copy />
              </Button>
            </div>
            <Button variant="outline" size="sm" className="self-start" onClick={() => setJustCreated(null)}>
              Done
            </Button>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <Input
            className="h-9 min-w-[160px] flex-1 bg-secondary"
            placeholder="Token name (e.g. ci-pipeline)"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <select
            className="h-9 rounded-md border border-input bg-secondary px-3 text-sm text-foreground"
            value={scope}
            onChange={(e) => setScope(e.target.value as ApiTokenScope)}
          >
            <option value="read">Read-only</option>
            <option value="read_write">Read/write</option>
          </select>
          <Button size="sm" disabled={creating || !name.trim()} onClick={create}>
            {creating ? "Creating..." : "Create token"}
          </Button>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex flex-col gap-2 border-t border-border pt-3">
          {tokens === null && <p className="text-xs text-muted-foreground">Loading...</p>}
          {tokens?.length === 0 && <p className="text-xs text-muted-foreground">No API tokens yet.</p>}
          {tokens?.map((t) => (
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
                  {t.token_prefix}... · created {new Date(t.created_at).toLocaleDateString()}
                  {t.last_used_at ? ` · last used ${new Date(t.last_used_at).toLocaleDateString()}` : " · never used"}
                </div>
              </div>
              {!t.revoked_at && (
                <Button
                  size="sm"
                  variant="outline"
                  className="shrink-0 text-destructive hover:text-destructive"
                  onClick={() => revoke(t.id)}
                >
                  Revoke
                </Button>
              )}
            </div>
          ))}
        </div>
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
];
const NOTIFICATION_CHANNELS: { value: NotificationChannel; label: string }[] = [
  { value: "slack", label: "Slack" },
  { value: "email", label: "Email (preference saved; delivery not yet implemented)" },
];

function ProfileSection() {
  const [me, setMe] = useState<AuthUser | null>(null);
  const [name, setName] = useState("");
  const [nameSaving, setNameSaving] = useState(false);
  const [nameSaved, setNameSaved] = useState(false);

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
    setNameSaving(true);
    setNameSaved(false);
    try {
      const updated = await api.updateMe(name);
      setMe(updated);
      setNameSaved(true);
    } finally {
      setNameSaving(false);
    }
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
              <Input className="bg-secondary" value={name} onChange={(e) => setName(e.target.value)} />
              <Button onClick={saveName} disabled={nameSaving} className="shrink-0">
                {nameSaving ? "Saving..." : "Save"}
              </Button>
            </div>
            {nameSaved && <span className="text-xs text-chart-5">Saved</span>}
          </div>
        </div>

        <div className="flex flex-col gap-3 border-t border-border pt-4">
          <h3 className="text-xs font-medium text-foreground">Change Password</h3>
          <Input
            type="password"
            placeholder="Current password"
            className="bg-secondary"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <Input
            type="password"
            placeholder="New password (min 8 characters)"
            className="bg-secondary"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <Input
            type="password"
            placeholder="Confirm new password"
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
            {pwSaved && <span className="text-xs text-chart-5">Password changed</span>}
          </div>
          {pwError && <p className="text-xs text-destructive">{pwError}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

function NotificationPreferencesSection() {
  const [prefs, setPrefs] = useState<Map<string, boolean>>(new Map());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.notificationPreferences().then((rows) => {
      const m = new Map<string, boolean>();
      for (const r of rows) m.set(`${r.channel}:${r.event_type}`, r.enabled);
      setPrefs(m);
      setLoading(false);
    });
  }, []);

  function toggle(channel: NotificationChannel, eventType: NotificationEventType) {
    const key = `${channel}:${eventType}`;
    setPrefs((prev) => {
      const next = new Map(prev);
      next.set(key, !next.get(key));
      return next;
    });
    setSaved(false);
  }

  async function save() {
    setSaving(true);
    try {
      const preferences: NotificationPreference[] = [];
      for (const channel of NOTIFICATION_CHANNELS) {
        for (const event of NOTIFICATION_EVENT_TYPES) {
          const key = `${channel.value}:${event.value}`;
          preferences.push({ channel: channel.value, event_type: event.value, enabled: prefs.get(key) ?? false });
        }
      }
      await api.setNotificationPreferences(preferences);
      setSaved(true);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-3 px-4 py-4">
          <Skeleton className="h-4 w-48" />
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-24 w-full" />
        </CardContent>
      </Card>
    );
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
                        checked={prefs.get(`${channel.value}:${event.value}`) ?? false}
                        onChange={() => toggle(channel.value, event.value)}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="flex items-center gap-3">
          <Button onClick={save} disabled={saving} className="self-start">
            {saving ? "Saving..." : "Save Preferences"}
          </Button>
          {saved && <span className="text-xs text-chart-5">Saved</span>}
        </div>
      </CardContent>
    </Card>
  );
}

function WorkspaceSection() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [form, setForm] = useState<Partial<Target>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.targets().then((ts) => {
      setTargets(ts);
      if (ts.length > 0) setTargetId(ts[0].id);
    });
  }, []);

  useEffect(() => {
    if (targetId === null) return;
    const target = targets.find((t) => t.id === targetId);
    if (target) setForm(target);
    setSaved(false);
  }, [targetId, targets]);

  async function save() {
    if (targetId === null) return;
    setSaving(true);
    try {
      const updated = await api.updateTarget(targetId, {
        default_branch: form.default_branch,
        label: form.label,
        criticality_weight: form.criticality_weight,
      });
      setTargets((prev) => prev.map((t) => (t.id === updated.id ? updated : t)));
      setSaved(true);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="mb-3 text-sm font-medium text-foreground">Target Configuration</h2>
        <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />
      </div>

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
              <Button onClick={save} disabled={saving}>
                {saving ? "Saving..." : "Save Changes"}
              </Button>
              {saved && <span className="text-xs text-chart-5">Saved</span>}
            </div>
          </CardContent>
        </Card>
      )}

      {targetId !== null && <WorkspaceKeyCard key={targetId} targetId={targetId} />}

      <ApiTokensCard />
    </div>
  );
}

// Issue #130: Settings was one long unsectioned scroll (Profile -> Password
// -> Notifications -> Target Configuration -> API key), inconsistent with
// Admin's grouped section-nav (#118) for a conceptually similar
// multi-section page. Reuses that exact pattern -- a strip of pill buttons,
// `min-w-0 overflow-x-auto` so an overflowing strip scrolls within its own
// bounded container instead of pushing width overflow up onto `<main>`
// (see #118's admin/page.tsx for the full mechanism writeup) -- so the two
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
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Settings</h1>
          <p className="text-sm text-muted-foreground">Profile, notifications, target configuration, and workspace credentials</p>
        </div>
        <Link href="/onboarding" className="text-xs text-accent-strong underline">
          Replay guided onboarding
        </Link>
      </div>

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
