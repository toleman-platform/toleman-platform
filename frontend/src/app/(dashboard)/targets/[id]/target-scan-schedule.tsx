"use client";

import { useState } from "react";
import { api, ScanScheduleType, ScanSchedulePatch, TargetScanSchedules } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { SkeletonList } from "@/components/ui/skeleton";
import { ScanScheduleRow } from "@/components/features/scans";

// Issue #306: per-target scan scheduling.
//
// Client component with its own fetch rather than data threaded down from
// the server page, for the same reason TargetGroups is: the values change as
// soon as you edit them and again every time the dispatcher fires, and a
// server-rendered snapshot would show a "next run" that silently ages for
// as long as the tab stays open.
export function TargetScanSchedule({ targetId }: { targetId: number }) {
  const [saving, setSaving] = useState<ScanScheduleType | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data, error: loadError, isInitialLoading, refetch } = useAsyncData<TargetScanSchedules>(
    () => api.targetScanSchedules(targetId),
    { deps: [targetId] },
  );

  async function save(scanType: ScanScheduleType, patch: ScanSchedulePatch) {
    setSaving(scanType);
    setError(null);
    try {
      await api.saveTargetScanSchedule(targetId, scanType, patch);
      refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to save the schedule");
    } finally {
      setSaving(null);
    }
  }

  async function reset(scanType: ScanScheduleType) {
    setSaving(scanType);
    setError(null);
    try {
      await api.resetTargetScanSchedule(targetId, scanType);
      refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to reset the schedule");
    } finally {
      setSaving(null);
    }
  }

  if (isInitialLoading) return <SkeletonList count={2} />;

  const message = error ?? loadError?.message ?? null;
  if (!data) {
    return (
      <div className="flex flex-col gap-2">
        {/* No silent empty state: if the schedule cannot be read, say so.
            Rendering nothing here would read as "this target has no
            schedule", which is a different and much more reassuring claim
            than "we could not find out". */}
        <p className="text-xs text-destructive">
          {message ?? "Could not load this target's scan schedule."}
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col divide-y divide-border rounded-md border border-border">
        {data.schedules.map((view) => (
          <ScanScheduleRow
            key={view.scan_type}
            view={view}
            scope="target"
            busy={saving === view.scan_type}
            disabledReason={
              // The thing the schedule itself cannot tell you: an armed
              // api_scan schedule can still be permanently inert, and there
              // are four separate ways for that to happen (the target is
              // deactivated, nuclei is off for the workspace's api_scan
              // surface, there is no API base URL, or nothing has been
              // discovered to probe). The server resolves which one from
              // the same function the dispatcher refuses on, so this cannot
              // drift from what actually happens at dispatch time.
              view.scan_type === "api_scan" && view.enabled && !data.api_scan_readiness.ready
                ? [
                    data.api_scan_readiness.detail ??
                      "This schedule will not probe anything in its current configuration.",
                    // The one reason whose fix is on this same page.
                    data.api_scan_readiness.reason === "no_api_base_url"
                      ? "Set one under Active API Scanning below."
                      : null,
                  ]
                    .filter(Boolean)
                    .join(" ")
                : null
            }
            onChange={(patch) => save(view.scan_type, patch)}
            onReset={() => reset(view.scan_type)}
          />
        ))}
      </div>
      {message && <p className="text-xs text-destructive">{message}</p>}
      <p className="text-xs text-muted-foreground">
        Changing a cadence restarts the clock from now, so switching a schedule on does not fire one
        immediately. Use the Scan buttons at the top of this page when you want one right away.
      </p>
    </div>
  );
}
