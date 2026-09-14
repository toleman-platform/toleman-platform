"use client";

import { useState } from "react";
import { api, ScanScheduleType, ScanSchedulePatch, WorkspaceScanSchedules, workspaceDisplayName } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useWorkspacePicker } from "@/hooks/features/use-workspace-picker";
import { Card, CardContent } from "@/components/ui/card";
import { SkeletonList } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { ScanScheduleRow } from "@/components/features/scans";
import { Building2, CalendarClock } from "lucide-react";

// Issue #306: workspace-level scan scheduling defaults.
//
// Mirrors the SLA Rules tab's workspace-picker-then-edit shape (#70), and
// for the same reason: these are per-workspace policy decisions an admin
// makes rarely and needs to see side by side with the workspace they apply
// to, not settings buried per target.
//
// Whatever is set here applies to every target in the workspace that has not
// overridden it on its own detail page; a target-level setting always wins.
export function ScanSchedules() {
  const { workspaces, workspaceId, setWorkspaceId, error: workspacesError } = useWorkspacePicker();
  const [saving, setSaving] = useState<ScanScheduleType | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);

  const { data, error: loadError, isInitialLoading: loading, refetch } =
    useAsyncData<WorkspaceScanSchedules>(() => api.workspaceScanSchedules(workspaceId!), {
      enabled: workspaceId != null,
      deps: [workspaceId],
    });

  const error = mutationError ?? loadError?.message ?? workspacesError?.message ?? null;

  async function save(scanType: ScanScheduleType, patch: ScanSchedulePatch) {
    if (!workspaceId) return;
    setSaving(scanType);
    setMutationError(null);
    try {
      await api.saveWorkspaceScanSchedule(workspaceId, scanType, patch);
      refetch();
    } catch (e) {
      setMutationError(e instanceof Error ? e.message : "failed to save the schedule");
    } finally {
      setSaving(null);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-border bg-card">
        <CardContent className="flex flex-col gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-accent-strong">
              <CalendarClock className="h-5 w-5" />
            </div>
            <div>
              <div className="font-medium text-foreground">Scheduled Scans</div>
              <div className="text-xs text-muted-foreground">
                How often this workspace&apos;s targets are scanned when nobody clicks anything. A
                target that sets its own schedule on its detail page overrides what is here; a
                target that does not, follows it. Requires the Celery beat process to be running.
              </div>
            </div>
          </div>

          {workspaces === null ? (
            <SkeletonList count={1} />
          ) : workspaces.length === 0 ? (
            <EmptyState
              icon={Building2}
              title="No workspaces yet"
              description="Connect a target first to create a workspace."
              bare
            />
          ) : (
            <select
              className="w-fit rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={workspaceId ?? ""}
              onChange={(e) => setWorkspaceId(Number(e.target.value))}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {workspaceDisplayName(w, workspaces)}
                </option>
              ))}
            </select>
          )}

          {workspaceId != null && (
            <>
              {error && <p className="text-xs text-destructive">{error}</p>}

              <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                {loading ? (
                  <div className="px-3 py-2">
                    <SkeletonList count={2} />
                  </div>
                ) : !data ? (
                  // Deliberately not an "empty" state: there is always an
                  // effective schedule, so nothing to show here means the
                  // read failed, and saying "no schedules" would be a
                  // reassuring claim we have no basis for.
                  <p className="px-3 py-3 text-xs text-destructive">
                    Could not load this workspace&apos;s scan schedules.
                  </p>
                ) : (
                  data.schedules.map((view) => (
                    <ScanScheduleRow
                      key={view.scan_type}
                      view={view}
                      scope="workspace"
                      busy={saving === view.scan_type}
                      disabledReason={
                        // Only the workspace-scoped refusal is asserted
                        // here. nuclei's api_scan surface is a property of
                        // this workspace, so when it is off no target will
                        // be probed and an armed schedule is simply inert --
                        // saying so is the same rule the target page now
                        // enforces. The other three reasons in
                        // ApiScanReadiness are per-target facts this view
                        // cannot know; they stay as the standing caveat
                        // below rather than a per-row error that might not
                        // apply to anything.
                        view.scan_type === "api_scan" && view.enabled && !data.api_scan_tool_enabled
                          ? "Active API scanning (nuclei) is switched off for this workspace in Tool Marketplace, so this schedule will not probe anything."
                          : null
                      }
                      onChange={(patch) => save(view.scan_type, patch)}
                    />
                  ))
                )}
              </div>

              {/* The three per-target reasons a scheduled API scan can be
                  skipped. Stated once here rather than as a per-row error,
                  because this view cannot know whether any of them apply:
                  telling an admin "no API base URL is set" on a workspace
                  where every target has one would be the same dishonesty
                  pointed the other way. Each target's detail page names the
                  one that actually applies to it. */}
              <p className="text-xs text-muted-foreground">
                A scheduled active API scan only reaches a target that is active, has an API base
                URL configured, and has discovered endpoints to probe. Any other target is skipped
                silently, and never probed at a host this platform inferred. Each target&apos;s
                Scheduled scans panel says which of these applies to it.
              </p>
              <p className="text-xs text-muted-foreground">
                Scheduled scans go through the same queue as manual ones, at the same concurrency.
                Shortening a cadence across a large workspace makes every run compete for that one
                queue rather than making results arrive sooner.
              </p>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
