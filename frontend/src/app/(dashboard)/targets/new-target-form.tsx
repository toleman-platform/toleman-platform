"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Building2 } from "lucide-react";
import { api, workspaceDisplayName } from "@/lib/api";
import { useWorkspacePicker } from "@/hooks/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonList } from "@/components/ui/skeleton";

const LABELS = ["Prod", "Dev", "Internal", "Public"];
const WEIGHT_BY_LABEL: Record<string, number> = { Prod: 5, Public: 4, Internal: 3, Dev: 2 };

export function NewTargetForm() {
  const router = useRouter();
  // Issue #356: this used to be a bare number input defaulting to a
  // hardcoded `1`, and the only place to look that number up was the
  // Workspaces page, which rendered workspaces as "Workspace #7". Worse,
  // the default was a lie on any fresh deployment: with no workspace rows
  // at all, submitting sent workspace_id=1 into a real FK column and the
  // resulting backend 500 reached the browser as a CORS error (see
  // create_target in backend/app/api/targets.py). The same hook every admin
  // panel already uses gives the actual list, so the id is chosen, never
  // typed, and "there are no workspaces yet" becomes a visible state with a
  // way out rather than a failed POST.
  const {
    workspaces,
    workspaceId,
    setWorkspaceId,
    isLoading: workspacesLoading,
    error: workspacesError,
  } = useWorkspacePicker();
  const [name, setName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [label, setLabel] = useState("Dev");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (workspaceId === null) {
      setError("pick a workspace first");
      return;
    }
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

  // A failed workspace load is not an empty workspace list, and rendering
  // one as the other is exactly what useWorkspacePicker exists to stop
  // (see its docstring). Surface it and keep the form out of the way; the
  // submit would 404 or 403 anyway with no id to send.
  if (workspacesError) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="px-4 py-4">
          <p className="text-xs text-destructive">
            Could not load workspaces: {workspacesError.message}
          </p>
        </CardContent>
      </Card>
    );
  }

  if (!workspacesLoading && workspaces !== null && workspaces.length === 0) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="px-4 py-4">
          <EmptyState
            icon={Building2}
            title="No workspaces yet"
            description="Every target belongs to a workspace. Create one, then come back and add this repository to it."
            action={
              <Button asChild size="sm">
                <Link href="/workspaces">Create a workspace</Link>
              </Button>
            }
            bare
          />
        </CardContent>
      </Card>
    );
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
              aria-label="Criticality label"
            >
              {LABELS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
            {workspacesLoading || workspaces === null ? (
              <SkeletonList count={1} />
            ) : (
              <select
                className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
                value={workspaceId ?? ""}
                onChange={(e) => setWorkspaceId(Number(e.target.value))}
                aria-label="Workspace"
              >
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {/* Same disambiguator the admin pickers use: real seeded
                        data has several workspaces named "default". */}
                    {workspaceDisplayName(w, workspaces)}
                  </option>
                ))}
              </select>
            )}
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
          <Button type="submit" disabled={submitting || workspaceId === null} className="self-start">
            {submitting ? "Adding..." : "Add Target"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
