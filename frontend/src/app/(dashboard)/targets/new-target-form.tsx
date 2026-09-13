"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Building2 } from "lucide-react";
import { api, workspaceDisplayName } from "@/lib/api";
import type { AuthUser, WorkspaceSummary } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/features/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { AsyncContent } from "@/components/ui/async-content";

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
  // typed, and every other state of that list is handled below by
  // AsyncContent rather than hand-rolled here.
  const { workspaceId, setWorkspaceId, state } = useWorkspacePicker();

  // GET /api/workspaces is filtered by accessible_workspace_ids, so an empty
  // list means two different things: for an admin (unfiltered) nothing
  // exists, for anyone else they are a member of nothing. Only the first is
  // fixable by the person looking at it; create_workspace is admin-gated, so
  // pointing a non-admin at /workspaces just hands them a 403. This fetch is
  // the same one the settings page already makes client-side.
  //
  // An unknown role (still loading, or /api/auth/me failed) deliberately
  // takes the non-admin copy: "ask an admin" is merely unhelpful to an
  // admin, while a create CTA that 403s is a dead end for everyone else.
  const { data: me } = useAsyncData<AuthUser>(() => api.me());
  const isAdmin = me?.role === "admin";

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

  return (
    <Card className="border-border bg-card">
      <CardContent className="px-4 py-4">
        <AsyncContent<WorkspaceSummary[]>
          state={state}
          itemNoun="workspaces"
          skeletonCount={1}
          errorTitle="Couldn't load workspaces"
          emptyIcon={Building2}
          emptyTitle={isAdmin ? "No workspaces yet" : "No workspaces available to you"}
          emptyDescription={
            isAdmin
              ? "Every target belongs to a workspace. Create one, then come back and add this repository to it."
              : "Every target belongs to a workspace, and you're not a member of any. Ask an admin to add you to one, or to create one."
          }
          emptyAction={
            isAdmin ? (
              <Button asChild size="sm">
                <Link href="/workspaces">Create a workspace</Link>
              </Button>
            ) : undefined
          }
        >
          {(workspaces) => (
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
              </div>
              {error && <p className="text-xs text-destructive">{error}</p>}
              <Button type="submit" disabled={submitting || workspaceId === null} className="self-start">
                {submitting ? "Adding..." : "Add Target"}
              </Button>
            </form>
          )}
        </AsyncContent>
      </CardContent>
    </Card>
  );
}
