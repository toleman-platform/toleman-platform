import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { ToolsHealth } from "./tools-health";

const toolsHealth = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: { toolsHealth } }));

afterEach(() => toolsHealth.mockReset());

function health(over: Partial<{ tool: string; installed: boolean; version: string | null; response_ms: number | null }> = {}) {
  return { tool: "semgrep", installed: true, version: "1.0.0", response_ms: 12, ...over };
}

describe("ToolsHealth", () => {
  it("shows a named checking card per known tool while the request is in flight", async () => {
    toolsHealth.mockReturnValue(new Promise(() => {})); // never resolves
    render(<ToolsHealth />);
    expect(await screen.findAllByText("checking")).toHaveLength(4);
    expect(screen.getByText("semgrep")).toBeDefined();
    expect(screen.getByText("gitleaks")).toBeDefined();
    expect(screen.getByText("trivy")).toBeDefined();
    expect(screen.getByText("gosec")).toBeDefined();
  });

  // A successful response that omits a known tool used to leave that card
  // reading "checking" forever, because the state was derived from
  // key-presence in the response rather than from the request's own status.
  it("shows 'not checked' rather than a stuck spinner for a tool missing from a successful response", async () => {
    toolsHealth.mockResolvedValue([health({ tool: "semgrep" })]);
    render(<ToolsHealth />);
    await screen.findByText("healthy");
    // gitleaks, trivy, gosec all missing from the response.
    expect(screen.getAllByText("not checked")).toHaveLength(3);
    expect(screen.queryByText("checking")).toBeNull();
  });

  // Cards used to be rendered only from the hardcoded TOOLS list, so a tool
  // the backend reports but that isn't in that list was silently dropped.
  it("renders a tool the backend reports even when it isn't in the known TOOLS list", async () => {
    toolsHealth.mockResolvedValue([health({ tool: "checkov", installed: true, version: "2.0.0" })]);
    render(<ToolsHealth />);
    expect(await screen.findByText("checkov")).toBeDefined();
  });

  it("shows 'not installed' for a checked tool the host doesn't have", async () => {
    toolsHealth.mockResolvedValue([health({ tool: "semgrep", installed: false, version: null })]);
    render(<ToolsHealth />);
    expect(await screen.findByText("not installed")).toBeDefined();
  });
});
