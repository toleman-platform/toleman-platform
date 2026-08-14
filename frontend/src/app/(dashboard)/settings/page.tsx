"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, AuthUser, NotificationChannel, NotificationEventType, NotificationPreference, Target } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";
import { Skeleton } from "@/components/ui/skeleton";

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

export default function SettingsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<number | null>(null);
  const [form, setForm] = useState<Partial<Target>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [workspaceKey, setWorkspaceKey] = useState<string | null>(null);

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
    api.workspaceKey(targetId).then((r) => setWorkspaceKey(r.api_key));
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
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Settings</h1>
          <p className="text-sm text-muted-foreground">Target configuration and workspace credentials</p>
        </div>
        <Link href="/onboarding" className="text-xs text-accent-strong underline">
          Replay guided onboarding
        </Link>
      </div>

      <ProfileSection />
      <NotificationPreferencesSection />

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

      {workspaceKey && (
        <Card className="border-border bg-card">
          <CardContent className="px-4 py-4">
            <p className="text-xs text-muted-foreground">Workspace API key (for CI push ingestion, X-API-Key header)</p>
            <code className="mt-1 block break-all text-sm text-foreground">{workspaceKey}</code>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
