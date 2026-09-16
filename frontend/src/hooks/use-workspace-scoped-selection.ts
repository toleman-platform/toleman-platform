"use client";

import { useState } from "react";

/**
 * A repo-picker selection that resets when the active workspace changes.
 *
 * A specific target id belongs to whichever workspace was active when it was
 * picked; switching the global workspace switcher must not leave that (now
 * likely out-of-scope) id selected underneath a freshly-scoped repo list --
 * `TargetPicker` only hides ids absent from its current `targets` prop, it
 * does not drop them from the selection it is handed, so every read/action/
 * export keyed off that state would otherwise keep reaching a target that
 * belongs to a workspace the reader has since switched away from. The
 * backend authorizes each target against its own workspace, not the
 * caller's *currently active* one, so a stale id is not merely a display
 * glitch: a developer with access to two workspaces could still read or
 * write a target in the one they just switched off of (#519 review).
 *
 * `allTargetsValue` (e.g. `ALL_TARGETS`) is exempt from the reset when
 * given: an org-wide selection re-scopes cleanly to the new workspace on
 * its own, and a switch should not kick the reader out of it.
 *
 * Returns `null` for "nothing explicitly chosen yet" (a caller falls back to
 * its own default -- usually the first repo, or `ALL_TARGETS`) and `[]` for
 * "explicitly cleared" -- these are NOT the same thing. `TargetPicker`'s
 * popover has its own Clear action, and a caller whose fallback expression
 * was `selection.length > 0 ? selection : default` could not tell the two
 * apart: clearing the picker produced an empty array, which read exactly
 * like "never touched" and silently snapped straight back to the default,
 * so the Clear button appeared to do nothing -- worse, on pages where the
 * fallback still fed live reads/actions/exports, a "cleared" selection kept
 * acting on the default target the reader had just deselected (#519
 * review). Callers must resolve the effective selection with `selection ??
 * default`, never `selection.length > 0 ? selection : default`, so an
 * explicit empty array stays empty.
 *
 * React's documented "adjust state when a prop changes" pattern, not an
 * effect, so the reset lands the same render the switch does (see
 * sidebar.tsx's `lastPathname`) -- this was previously duplicated inline in
 * sbom/page.tsx; every other page carrying a workspace-scoped selection
 * should use this instead of re-deriving it.
 */
export function useWorkspaceScopedSelection(
  activeWorkspaceId: number | null,
  allTargetsValue?: number,
  initial: number[] | null | (() => number[] | null) = null,
): [number[] | null, (ids: number[]) => void] {
  const [ids, setIds] = useState<number[] | null>(initial);
  const [lastWorkspaceId, setLastWorkspaceId] = useState(activeWorkspaceId);
  if (lastWorkspaceId !== activeWorkspaceId) {
    setLastWorkspaceId(activeWorkspaceId);
    // A workspace switch resets back to "nothing explicitly chosen" (not to
    // `[]`): the point is to let each page's default apply to the *new*
    // workspace, not to freeze the picker cleared forever.
    if (allTargetsValue === undefined || !(ids ?? []).includes(allTargetsValue)) {
      setIds(null);
    }
  }
  return [ids, setIds];
}
