import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { ToolsHealth } from "./tools-health";

const toolsHealth = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: { toolsHealth } }));

afterEach(() => toolsHealth.mockReset());

type Health = {
  tool: string;
  installed: boolean | null;
  version: string | null;
  response_ms: number | null;
  checked_in: string | null;
};

function health(over: Partial<Health> = {}): Health {
  return { tool: "semgrep", installed: true, version: "1.0.0", response_ms: 12, checked_in: "api", ...over };
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

  // The reported defect: a tool installed from the marketplace lives on the
  // Celery worker, not next to the web process, so the api-side probe can
  // never see it. The page has to report the tool, not the probe.
  it("shows a worker-reported tool as healthy and names where it runs", async () => {
    toolsHealth.mockResolvedValue([
      health({ tool: "checkov", installed: true, version: "3.3.13", response_ms: null, checked_in: "worker" }),
    ]);
    render(<ToolsHealth />);

    expect(await screen.findByText("healthy")).toBeTruthy();
    expect(screen.getByText("on scan worker")).toBeTruthy();
    expect(screen.queryByText("not installed")).toBeNull();
  });

  it("does not claim a locally visible tool runs on the worker", async () => {
    toolsHealth.mockResolvedValue([health({ tool: "semgrep", checked_in: "api" })]);
    render(<ToolsHealth />);

    expect(await screen.findByText("healthy")).toBeTruthy();
    expect(screen.queryByText("on scan worker")).toBeNull();
  });

  // installed: null means no process that would run this tool has reported
  // on it. Rendering that as the same red "not installed" the confident
  // negative above gets is the AGENTS.md 1.4 violation this page shipped.
  it("shows 'unverified' rather than 'not installed' when nothing has reported on a tool", async () => {
    toolsHealth.mockResolvedValue([
      health({ tool: "tfsec", installed: null, version: null, response_ms: null, checked_in: null }),
    ]);
    render(<ToolsHealth />);

    expect(await screen.findByText("unverified")).toBeTruthy();
    expect(screen.queryByText("not installed")).toBeNull();
  });

  it("distinguishes unverified, not installed and healthy in one response", async () => {
    toolsHealth.mockResolvedValue([
      health({ tool: "semgrep", installed: true, version: "1.136.0" }),
      health({ tool: "checkov", installed: false, version: null, response_ms: null, checked_in: "worker" }),
      health({ tool: "tfsec", installed: null, version: null, response_ms: null, checked_in: null }),
    ]);
    render(<ToolsHealth />);

    await screen.findByText("healthy");
    expect(screen.getAllByText("not installed")).toHaveLength(1);
    expect(screen.getAllByText("unverified")).toHaveLength(1);
    // gitleaks, trivy and gosec are absent from the response entirely, which
    // is a different unknown from tfsec's reported-but-unverified one.
    expect(screen.getAllByText("not checked")).toHaveLength(3);
  });
});
