"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Building2 } from "lucide-react";
import { api, workspaceDisplayName } from "@/lib/api";
import type { WorkspaceSummary } from "@/lib/api";
import { useWorkspacePicker } from "@/hooks/features/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { AsyncContent } from "@/components/ui/async-content";

const LABELS = ["Prod", "Dev", "Internal", "Public"];
const WEIGHT_BY_LABEL: Record<string, number> = { Prod: 5, Public: 4, Internal: 3, Dev: 2 };

export function NewTargetForm({
  /** Whether the caller can create a workspace, resolved server-side by the
   * page (#356). `null` means the role could not be determined at all
   * (/api/auth/me failed), which is neither "admin" nor "not a member" and
   * must not be rendered as either. */
  isAdmin,
}: {
  isAdmin: boolean | null;
}) {
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
          // Three states, because an empty list means something different to
          // each of them and only one of the three can act on it. An admin
          // sees the unfiltered list, so empty really does mean none exist;
          // anyone else sees only their memberships, so empty means they
          // hold none, and /workspaces would 403 them. When the role is
          // unknown the copy asserts neither: withholding the action is
          // cheap, claiming a membership fact the page never established is
          // not.
          emptyTitle={isAdmin ? "No workspaces yet" : "No workspaces available"}
          emptyDescription={
            isAdmin
              ? "Every target belongs to a workspace. Create one, then come back and add this repository to it."
              : isAdmin === false
                ? "Every target belongs to a workspace, and you're not a member of any. Ask an admin to add you to one, or to create one."
                : "Every target belongs to a workspace. Create one on the Workspaces page, or ask an admin to add you to an existing one."
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
