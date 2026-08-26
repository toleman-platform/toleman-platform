import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { useWorkspacePicker } from "./use-workspace-picker";

const workspaces = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  api: { workspaces },
  workspaceDisplayName: (w: { name: string }) => w.name,
}));

afterEach(() => workspaces.mockReset());

describe("useWorkspacePicker", () => {
  it("defaults to the first workspace once the list resolves", async () => {
    workspaces.mockResolvedValue([{ id: 7 }, { id: 9 }]);
    const { result } = renderHook(() => useWorkspacePicker());
    await waitFor(() => expect(result.current.workspaceId).toBe(7));
  });

  it("has no selection before the list arrives", () => {
    workspaces.mockReturnValue(new Promise(() => {}));
    const { result } = renderHook(() => useWorkspacePicker());
    // Not zero, not the first id of a list nobody has seen; null, so the
    // scoped fetch below stays disabled rather than requesting workspace 0.
    expect(result.current.workspaceId).toBeNull();
    expect(result.current.isLoading).toBe(true);
  });

  it("keeps the user's choice when the list reloads", async () => {
    // The bug this hook exists to prevent: seeding the selection inside a
    // `.then` meant any later refetch could snap the user back to workspace
    // one mid-task.
    workspaces.mockResolvedValue([{ id: 7 }, { id: 9 }]);
    const { result } = renderHook(() => useWorkspacePicker());
    await waitFor(() => expect(result.current.workspaceId).toBe(7));

    act(() => result.current.setWorkspaceId(9));
    expect(result.current.workspaceId).toBe(9);

    act(() => result.current.reload());
    await waitFor(() => expect(workspaces).toHaveBeenCalledTimes(2));
    expect(result.current.workspaceId).toBe(9);
  });

  it("surfaces a failed workspace load instead of looking empty", async () => {
    // Every panel that hand-rolled this dropped the rejection, so a failed
    // request rendered as "no workspaces exist"; a claim the page had not
    // earned.
    workspaces.mockRejectedValue(new Error("503"));
    const { result } = renderHook(() => useWorkspacePicker());
    await waitFor(() => expect(result.current.error?.message).toBe("503"));
    expect(result.current.workspaces).toBeNull();
    expect(result.current.workspaceId).toBeNull();
  });

  it("reports a genuinely empty list as empty, not as loading", async () => {
    workspaces.mockResolvedValue([]);
    const { result } = renderHook(() => useWorkspacePicker());
    await waitFor(() => expect(result.current.workspaces).toEqual([]));
    expect(result.current.isLoading).toBe(false);
    expect(result.current.workspaceId).toBeNull();
  });

  it("allows clearing the selection back to the default", async () => {
    workspaces.mockResolvedValue([{ id: 7 }, { id: 9 }]);
    const { result } = renderHook(() => useWorkspacePicker());
    await waitFor(() => expect(result.current.workspaceId).toBe(7));

    act(() => result.current.setWorkspaceId(9));
    act(() => result.current.setWorkspaceId(null));
    expect(result.current.workspaceId).toBe(7);
  });
});
