import { render, type RenderResult } from "@testing-library/react";
import { WorkspaceProvider } from "@/contexts/workspace-context";

/**
 * Renders a component that reads `useWorkspaceContext()` (issue #506) with a
 * real `WorkspaceProvider` around it, so the test drives the provider's
 * actual fetch/persist logic through a mocked `api.workspaces()` (see each
 * test file's own `vi.mock("@/lib/api", ...)`) rather than mocking the
 * context itself. `userId: null` (no per-user localStorage key) unless the
 * test cares about persistence specifically.
 */
export function renderWithWorkspace(ui: React.ReactElement, userId: number | null = null): RenderResult {
  return render(<WorkspaceProvider userId={userId}>{ui}</WorkspaceProvider>);
}
