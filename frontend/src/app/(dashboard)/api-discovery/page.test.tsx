import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import ApiDiscoveryPage from "./page";
import type { Endpoint, ScanRun, Target } from "@/lib/api";
import { renderWithWorkspace } from "@/test/render-with-workspace";

/**
 * Three bugs observed live, all covered here:
 *
 *  1. discovery.py's django/spring fallback (no derivable HTTP method, and a
 *     django regex that accepts a zero-length route) produced a "-" method
 *     row, an empty-route row, and a "..." route row -- none of them a real
 *     discovered route. The page must drop them rather than render them.
 *  2. A failed active scan rendered as an unstyled <p>, indistinguishable
 *     from the "N findings" sentence above it. It must render as the same
 *     AlertBanner the rest of the app uses for a write-action failure.
 *  3. 134 endpoints at ~100px per row (a bare Card/CardContent, missing the
 *     `py-0` override ListRow already carries) was 13,000px of scroll, and
 *     two same-route rows were distinguishable only by a small grey
 *     file:line buried behind a bullet. The table must be dense (ListRow),
 *     grouped by method, and give file:line its own legible slot.
 */
const { targets, getDiscoveredEndpoints, getLatestApiScan, setEndpointScope, runApiScan, runDiscovery, workspaces } =
  vi.hoisted(() => ({
    targets: vi.fn(),
    getDiscoveredEndpoints: vi.fn(),
    getLatestApiScan: vi.fn(),
    setEndpointScope: vi.fn(),
    runApiScan: vi.fn(),
    runDiscovery: vi.fn(),
    // The repo picker now reads the global workspace switcher (#520), which
    // needs a WorkspaceProvider ancestor -- see renderWithWorkspace below.
    workspaces: vi.fn(),
  }));

vi.mock("@/lib/api", () => ({
  api: { targets, getDiscoveredEndpoints, getLatestApiScan, setEndpointScope, runApiScan, runDiscovery, workspaces },
}));

// The active-scan poll loop (queued -> running -> settled) is exercised by
// use-scan-run.test.ts; these tests only need a fixed idle phase so
// `lastApiScan` resolves from the persisted GET, not a scan just dispatched
// in this session.
vi.mock("@/hooks/features/use-scan-run", () => ({
  useScanRun: () => ({
    phase: null,
    elapsedSeconds: 0,
    etaSeconds: null,
    error: null,
    health: "unknown",
    healthNote: "",
    track: vi.fn(),
    fail: vi.fn(),
    reset: vi.fn(),
  }),
}));

function target(over: Partial<Target> = {}): Target {
  return {
    id: 1,
    workspace_id: 1,
    name: "svc",
    repo_url: "https://github.com/acme/svc",
    default_branch: "main",
    label: "Internal",
    criticality_weight: 2,
    groups: [],
    pipeline_integrated: false,
    pipeline_pr_url: null,
    is_ai_repo: false,
    is_ai_repo_signals: "",
    is_ai_repo_override: null,
    is_ai_repo_effective: false,
    enforcement_mode: null,
    api_base_url: "https://api.example.com",
    diff_scoped_pr_scans: false,
    dependency_sync_status: null,
    dependency_sync_error: null,
    dependency_sync_at: null,
    dependency_component_count: null,
    is_active: true,
    deactivated_at: null,
    deleted_at: null,
    ...over,
  } as Target;
}

let nextId = 1;
function endpoint(over: Partial<Endpoint> = {}): Endpoint {
  return {
    id: nextId++,
    framework: "fastapi",
    method: "GET",
    route: "/users",
    file: "app/routes.py",
    line: 10,
    is_new: false,
    first_seen: "2024-01-01T00:00:00Z",
    last_seen: "2024-01-01T00:00:00Z",
    excluded: false,
    exclusion_reason: null,
    ...over,
  };
}

function scanRun(over: Partial<ScanRun> = {}): ScanRun {
  return {
    scan_id: 9,
    target_id: 1,
    tool: "api-scan",
    branch: "main",
    status: "completed",
    findings_count: 0,
    started_at: "2024-01-01T00:00:00Z",
    completed_at: "2024-01-01T00:05:00Z",
    error_message: "",
    elapsed_seconds: 300,
    eta_seconds: null,
    health: "healthy",
    health_note: "",
    ...over,
  };
}

beforeEach(() => {
  nextId = 1;
  targets.mockReset();
  getDiscoveredEndpoints.mockReset();
  getLatestApiScan.mockReset();
  setEndpointScope.mockReset();
  runApiScan.mockReset();
  runDiscovery.mockReset();
  targets.mockResolvedValue([target()]);
  getLatestApiScan.mockResolvedValue({ target_id: 1, scan: null });
  workspaces.mockResolvedValue([]);
});

describe("extraction-artefact filtering", () => {
  it("drops rows whose ROUTE did not extract, keeping genuine ones", async () => {
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 5,
      endpoints: [
        endpoint({ method: "-", route: "" }),
        endpoint({ method: "-", route: "..." }),
        // The production case: discovery.py's django fallback matched a bare
        // `path("...")` call inside a FastAPI repo's test file and tagged it
        // "django". It is dropped for its unusable ROUTE, not its method --
        // see the next test for why the method must not be the signal.
        endpoint({ framework: "django", method: "-", route: "...", file: "backend/tests/test_runner.py", line: 33 }),
        endpoint({ method: "GET", route: "/active", file: "app/a.py", line: 1 }),
        endpoint({ method: "GET", route: "/active", file: "app/b.py", line: 2 }),
      ],
    });

    renderWithWorkspace(<ApiDiscoveryPage />);

    expect(await screen.findByText("2 endpoints found")).not.toBeNull();
    expect(screen.queryByText(/backend\/tests\/test_runner\.py/)).toBeNull();
    // Both real "/active" registrations survive -- filtering removes
    // artefacts, not legitimate duplicate routes.
    expect(screen.getAllByText("/active").length).toBe(2);
  });

  it("keeps a django route even though its method is '-'", async () => {
    // discovery.py's django and spring branches both fall through to
    // `method, route = "-", groups[0]` -- neither framework encodes the HTTP
    // method at the route declaration, so "-" there means "unknown method",
    // not "failed extraction". An earlier version of the artefact filter
    // keyed on `method === "-"` and would have silently deleted every Django
    // and Spring endpoint the scanner found, while the page went on claiming
    // to list all of them.
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 2,
      endpoints: [
        endpoint({ framework: "django", method: "-", route: "/admin/users", file: "urls.py", line: 12 }),
        endpoint({ framework: "spring", method: "-", route: "/api/orders", file: "OrderController.java", line: 40 }),
      ],
    });

    renderWithWorkspace(<ApiDiscoveryPage />);

    expect(await screen.findByText("2 endpoints found")).not.toBeNull();
    expect(screen.getByText("/admin/users")).not.toBeNull();
    expect(screen.getByText("/api/orders")).not.toBeNull();
  });

  it("keeps a genuine route with a normal method untouched", async () => {
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 1,
      endpoints: [endpoint({ method: "POST", route: "/users/:id/replies" })],
    });

    renderWithWorkspace(<ApiDiscoveryPage />);

    expect(await screen.findByText("1 endpoint found")).not.toBeNull();
    expect(screen.getByText("/users/:id/replies")).not.toBeNull();
  });
});

describe("active scan failure state", () => {
  it("renders a failed scan as an alert, not a plain sentence", async () => {
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 1,
      endpoints: [endpoint()],
    });
    getLatestApiScan.mockResolvedValue({
      target_id: 1,
      scan: scanRun({ status: "failed", error_message: "nuclei scan timed out after retries" }),
    });

    renderWithWorkspace(<ApiDiscoveryPage />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Last active scan failed");
    expect(alert.textContent).toContain("nuclei scan timed out after retries");
  });

  it("still renders the completed-scan summary as plain text, not an alert", async () => {
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 1,
      endpoints: [endpoint()],
    });
    getLatestApiScan.mockResolvedValue({
      target_id: 1,
      scan: scanRun({ status: "completed", findings_count: 3 }),
    });

    renderWithWorkspace(<ApiDiscoveryPage />);

    expect(await screen.findByText(/Last active scan: 3 findings/)).not.toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("dense grouped table", () => {
  it("groups rows under a method header and exposes a framework facet", async () => {
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 2,
      endpoints: [
        endpoint({ method: "POST", route: "/b", framework: "express" }),
        endpoint({ method: "GET", route: "/a", framework: "fastapi" }),
      ],
    });

    const { container } = renderWithWorkspace(<ApiDiscoveryPage />);

    await screen.findByText("/a");
    // Conventional verb order: GET's group (and its one route) renders
    // ahead of POST's, regardless of the order discovery returned them in.
    const text = container.textContent ?? "";
    expect(text.indexOf("/a")).toBeLessThan(text.indexOf("/b"));
    expect(screen.getByLabelText("Filter by framework")).not.toBeNull();
    // "fastapi"/"express" each appear twice (the facet's <option> and the
    // row's own framework tag); asserting presence, not uniqueness, is the
    // point here.
    expect(screen.getAllByText("fastapi").length).toBeGreaterThan(0);
    expect(screen.getAllByText("express").length).toBeGreaterThan(0);
  });

  it("narrows the table to one framework and keeps bulk-scan scoped to what is shown", async () => {
    getDiscoveredEndpoints.mockResolvedValue({
      target_id: 1,
      count: 2,
      endpoints: [
        endpoint({ method: "GET", route: "/a", framework: "fastapi" }),
        endpoint({ method: "GET", route: "/b", framework: "express" }),
      ],
    });

    renderWithWorkspace(<ApiDiscoveryPage />);
    await screen.findByText("/a");

    fireEvent.change(screen.getByLabelText("Filter by framework"), { target: { value: "fastapi" } });

    expect(screen.getByText("/a")).not.toBeNull();
    expect(screen.queryByText("/b")).toBeNull();
    // "Scan all" now reads as the one route the facet leaves visible, not
    // the word "all" quietly covering the hidden Express route too.
    expect(screen.getByText("Scan 1 shown for vulnerabilities")).not.toBeNull();
  });
});
