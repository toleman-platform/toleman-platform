"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const LABELS = ["Prod", "Dev", "Internal", "Public"];
const WEIGHT_BY_LABEL: Record<string, number> = { Prod: 5, Public: 4, Internal: 3, Dev: 2 };

export function NewTargetForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [label, setLabel] = useState("Dev");
  const [workspaceId, setWorkspaceId] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.createTarget({
        workspace_id: workspaceId,
        name,
        repo_url: repoUrl,
        default_branch: branch,
        label,
        criticality_weight: WEIGHT_BY_LABEL[label] ?? 1,
      });
      setName("");
      setRepoUrl("");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create target");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="border-border bg-card">
      <CardContent className="px-4 py-4">
        <form onSubmit={onSubmit} className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3">
            <Input
              className="bg-secondary text-sm"
              placeholder="Target name (e.g. govwa)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <Input
              className="bg-secondary text-sm"
              placeholder="Repo URL (https://github.com/org/repo)"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              required
            />
            <Input
              className="bg-secondary text-sm"
              placeholder="Default branch"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
            />
            <select
              className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            >
              {LABELS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
            <Input
              type="number"
              className="bg-secondary text-sm"
              placeholder="Workspace ID"
              value={workspaceId}
              onChange={(e) => setWorkspaceId(Number(e.target.value))}
            />
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
          <Button type="submit" disabled={submitting} className="self-start">
            {submitting ? "Adding..." : "Add Target"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
