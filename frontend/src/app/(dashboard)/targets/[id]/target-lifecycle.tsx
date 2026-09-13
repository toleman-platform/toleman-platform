"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Power, PowerOff, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";

// (#273) Deactivate / reactivate / delete for one target.
//
// Worded as a choice between two different things rather than two buttons
// that both sound like "get rid of this". The distinction is the whole
// feature, and the copy is where a reader actually learns it:
//
//   Deactivate  scanning stops everywhere (on-demand, CI push, PR
//               Guardrail, active API scanning, the nightly refresh). The
//               target, its findings and its history stay. Reversible.
//   Delete      the target disappears from every list, dashboard and
//               report. Its findings and scan history are retained and
//               remain answerable through the audit log -- this is a
//               security tool, and "someone deleted the record of a
//               finding" is a question that has to keep having an answer.
//
// Delete routes through #118's shared ConfirmDialog, like every other
// destructive action in Admin; deactivate deliberately does not, because it
// is reversible in one click and a confirmation on a reversible toggle
// trains people to dismiss confirmations.
export function TargetLifecycle({
  targetId,
  targetName,
  initialIsActive,
}: {
  targetId: number;
  targetName: string;
  initialIsActive: boolean;
}) {
  const router = useRouter();
  const [isActive, setIsActive] = useState(initialIsActive);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  async function toggleActive() {
    setBusy(true);
    setError(null);
    const next = !isActive;
    // Optimistic, then reverted on failure -- same shape as
    // TargetDiffScope's own switch. router.refresh() afterwards so the
    // header banner and every other server-rendered part of this page
    // agree with the toggle rather than only this component knowing.
    setIsActive(next);
    try {
      if (next) await api.reactivateTarget(targetId);
      else await api.deactivateTarget(targetId);
      router.refresh();
    } catch (e) {
      setIsActive(!next);
      setError(e instanceof Error ? e.message : "failed to change scanning state");
    } finally {
      setBusy(false);
    }
  }

  async function confirmDelete() {
    setDeleting(true);
    setError(null);
    try {
      await api.deleteTarget(targetId);
      // Back to the list: this page's own subject no longer exists, so
      // staying here would render a 404 on the next refresh.
      router.push("/targets");
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete target");
      setDeleting(false);
      setConfirmingDelete(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-border p-3">
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">
            {isActive ? "Scanning is on" : "Scanning is off"}
          </div>
          <p className="mt-1 max-w-xl text-xs text-muted-foreground">
            {isActive
              ? "On-demand scans, CI pushes, PR Guardrail, active API scanning and the nightly baseline refresh all run for this target."
              : "Every scan path is refused for this target: on-demand, CI push ingestion, PR Guardrail, active API scanning and the nightly baseline refresh. Existing findings and history are kept and still count toward dashboards."}
          </p>
        </div>
        <Button
          variant={isActive ? "outline" : "default"}
          size="sm"
          disabled={busy}
          onClick={toggleActive}
          className="shrink-0"
        >
          {isActive ? <PowerOff className="h-3.5 w-3.5" /> : <Power className="h-3.5 w-3.5" />}
          {busy ? "Working..." : isActive ? "Deactivate" : "Reactivate"}
        </Button>
      </div>

      <div className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-destructive/30 p-3">
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">Delete this target</div>
          <p className="mt-1 max-w-xl text-xs text-muted-foreground">
            Removes it from every list, dashboard, score and report. Findings, scan history and PR Guardrail
            records are retained and stay visible in the audit log, so a deletion never erases the evidence
            that a finding existed.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="shrink-0 border-destructive/40 text-destructive hover:bg-destructive/10"
          onClick={() => setConfirmingDelete(true)}
        >
          <Trash2 className="h-3.5 w-3.5" />
          Delete
        </Button>
      </div>

      {error && <p className="text-xs text-destructive">{error}</p>}

      <ConfirmDialog
        open={confirmingDelete}
        title="Delete target"
        description={
          <>
            Delete <span className="font-medium text-foreground">{targetName}</span>? It disappears from every
            list, dashboard and report, and stops being scanned.
            <span className="mt-2 block">
              Its findings and scan history are <span className="font-medium text-foreground">kept</span> and
              remain visible in the audit log. If you only want to stop scanning, deactivate instead.
            </span>
          </>
        }
        confirmLabel="Delete target"
        tone="destructive"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setConfirmingDelete(false)}
      />
    </div>
  );
}
