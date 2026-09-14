"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Power, PowerOff, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";

// (#273) Per-row deactivate/reactivate and delete on the Targets list.
//
// Two small ghost icon buttons in a fixed-width column, not a dropdown
// menu: this repo has no menu primitive, and #224 deliberately stripped
// this page back to one bordered container with hairline dividers, so
// adding a floating popover per row would undo that. Icon-only with
// title + aria-label keeps the row width unchanged at 35+ rows while
// staying reachable by keyboard and screen reader.
//
// Rendered OUTSIDE the row's <Link> wrapper. Nesting interactive controls
// inside an anchor is invalid HTML and, in practice, means every click on
// Delete also navigates.
export function TargetRowActions({
  targetId,
  targetName,
  isActive,
}: {
  targetId: number;
  targetName: string;
  isActive: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function toggleActive() {
    setBusy(true);
    setError(null);
    try {
      if (isActive) await api.deactivateTarget(targetId);
      else await api.reactivateTarget(targetId);
      // No optimistic local state here, unlike the detail page's toggle:
      // this row's `isActive` is a prop from a server-rendered list, and
      // holding a second copy of it in component state is how a row ends
      // up disagreeing with the badge beside it after a refresh.
      router.refresh();
    } catch (e) {
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
      setConfirmingDelete(false);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to delete target");
      setConfirmingDelete(false);
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="flex w-16 shrink-0 items-center justify-end gap-0.5">
      {error && (
        // Inline rather than a toast: the failure belongs to this row, and
        // the most likely cause (403 -- delete needs security_engineer) is
        // specific enough that the real message is worth showing.
        <span className="mr-1 max-w-24 truncate text-[10px] text-destructive" title={error}>
          {error}
        </span>
      )}
      <Button
        variant="ghost"
        size="icon-sm"
        disabled={busy}
        onClick={toggleActive}
        aria-label={isActive ? `Deactivate ${targetName}` : `Reactivate ${targetName}`}
        title={
          isActive
            ? "Stop scanning this target. Findings and history are kept; it stays in this list."
            : "Resume scanning this target."
        }
        className="text-muted-foreground hover:text-foreground"
      >
        {isActive ? <PowerOff className="h-3.5 w-3.5" /> : <Power className="h-3.5 w-3.5" />}
      </Button>
      <Button
        variant="ghost"
        size="icon-sm"
        onClick={() => setConfirmingDelete(true)}
        aria-label={`Delete ${targetName}`}
        title="Remove this target. Its findings and scan history are retained in the audit log."
        className="text-muted-foreground hover:text-destructive"
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>

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
