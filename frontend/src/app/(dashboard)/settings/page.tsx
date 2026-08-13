"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Target } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { TargetPicker } from "@/components/target-picker";

const LABELS = ["Prod", "Dev", "Internal", "Public"];

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
        <Link href="/onboarding" className="text-xs text-primary underline">
          Replay guided onboarding
        </Link>
      </div>

      <TargetPicker targets={targets} value={targetId} onChange={setTargetId} />

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
