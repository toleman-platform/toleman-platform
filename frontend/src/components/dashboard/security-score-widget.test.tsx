import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { WidgetBody } from "./widgets";
import type { SecurityScore } from "@/lib/api";
import { renderWithWorkspace as render } from "@/test/render-with-workspace";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      // The widget loads the scope picker's options on mount. Neither list is
      // under test here, and resolving both empty leaves the picker with just
      // its org-wide default rather than reaching for the network.
      targets: () => Promise.resolve([]),
      groups: () => Promise.resolve([]),
      // No active workspace, same as an admin with the global switcher on
      // "All workspaces" -- keeps this file's existing "org" default intact.
      workspaces: () => Promise.resolve([]),
    },
  };
});

beforeEach(() => {
  // jsdom implements no matchMedia, and the gauge reads one to decide whether
  // to animate its numeral in. `matches: false` is the ordinary motion path.
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function baseScore(): SecurityScore {
  return {
    score: 72,
    grade: "C",
    target_count: 4,
    weakest_component: null,
    components: {
      findings: {
        score: 61,
        weight: 0.4,
        measurable: true,
        open_findings: 12,
        open_vulnerabilities: 9,
        license_findings_excluded: 3,
        weighted_severity_sum: 30,
        avg_weighted_severity_per_target: 7.5,
      },
      sla: { score: 88, weight: 0.2, measurable: true, with_sla: 10, in_violation: 2, compliant: 8, note: null },
      coverage: {
        score: 100,
        weight: 0.2,
        measurable: true,
        scanned_targets: 4,
        total_targets: 4,
        deactivated_targets: 0,
        window_days: 30,
        note: null,
      },
      fp_rate: {
        score: 95,
        weight: 0.1,
        measurable: true,
        false_positives: 1,
        total_findings: 20,
        fp_rate: 0.05,
      },
      trend: {
        score: 50,
        weight: 0.1,
        measurable: true,
        direction: "stable",
        current_weighted_sum: 30,
        prior_weighted_sum: 30,
        window_days: 7,
        note: null,
      },
    },
  };
}

function renderScore(score: SecurityScore) {
  return render(<WidgetBody entry={{ widget_id: "security_score", data: score }} />);
}

function rows(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>("[data-score-component]"));
}

function row(key: string): HTMLElement {
  const el = document.querySelector<HTMLElement>(`[data-score-component="${key}"]`);
  if (!el) throw new Error(`no breakdown row rendered for "${key}"`);
  return el;
}

function figureText(key: string): string {
  return row(key).querySelector<HTMLElement>("[data-score-figure]")?.textContent ?? "";
}

describe("Security Score widget - component breakdown columns", () => {
  it("puts every label, meter and figure on the same three tracks", () => {
    renderScore(baseScore());

    const all = rows();
    expect(all.map((r) => r.getAttribute("data-score-component"))).toEqual([
      "findings",
      "sla",
      "coverage",
      "fp_rate",
      "trend",
    ]);

    // The defect being guarded: rows that laid themselves out independently
    // (a `justify-between` line each) started their meter wherever that row's
    // own label happened to end, so the figures never formed a column. One
    // shared explicit grid template across every row is what makes them line
    // up, so assert there is exactly one, and that it is really declared.
    const templates = new Set(
      all.map((r) =>
        r.className
          .split(/\s+/)
          .filter((c) => c.startsWith("grid-cols-"))
          .join(" "),
      ),
    );
    expect(templates.size).toBe(1);
    expect([...templates][0]).not.toBe("");

    // Three cells per row, figure last, for measurable and unmeasurable rows
    // alike -- a row that emitted a different number of cells would push its
    // own figure out of the column.
    for (const r of all) {
      expect(r.children.length).toBe(3);
      expect(r.children[2].getAttribute("data-score-figure")).not.toBeNull();
    }

    expect(figureText("findings")).toBe("61/100");
    expect(figureText("sla")).toBe("88/100");
    expect(figureText("coverage")).toBe("100/100");
    expect(figureText("fp_rate")).toBe("95/100");
    expect(figureText("trend")).toBe("50/100");

    // Each figure is in its own label's row, not merely somewhere on the card.
    expect(row("findings").textContent).toContain("Open findings score");
    expect(row("findings").textContent).toContain("61/100");
    expect(row("coverage").textContent).toContain("Scan coverage score");
    expect(row("coverage").textContent).toContain("100/100");

    // Tabular figures, so digits in that column sit on a fixed pitch and the
    // numbers stay readable downwards.
    for (const r of all) {
      const figure = r.querySelector<HTMLElement>("[data-score-figure]");
      expect(figure).not.toBeNull();
      expect(figure?.className.split(/\s+/)).toContain("font-tabular");
    }
  });

  it("keeps the scope control with the headline score it rescopes", () => {
    renderScore(baseScore());

    const select = screen.getByLabelText("Scope") as HTMLSelectElement;
    expect(select.tagName).toBe("SELECT");
    expect(select.value).toBe("org");

    // The gauge is the headline the scope describes, and it reports the same
    // score the breakdown rolls up to.
    expect(screen.getByRole("img", { name: /Security score 72 out of 100/ })).not.toBeNull();
  });
});

// (dashboard scope picker follow-up) Previously "org-wide" was the only
// option and it silently meant "the caller's whole accessible set" even
// with a specific workspace active in the global switcher, and the
// Groups/Repositories lists it populated were never scoped to that
// workspace either -- an unsorted, cross-workspace dump with no way to
// tell which repo belonged to the workspace actually being looked at.
describe("Security Score widget - scoped to the active workspace", () => {
  it("defaults to the active workspace, not the full org, and needs no extra fetch for it", async () => {
    const securityScore = vi.fn();
    vi.doMock("@/lib/api", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/lib/api")>();
      return {
        ...actual,
        api: {
          ...actual.api,
          targets: () => Promise.resolve([]),
          groups: () => Promise.resolve([]),
          workspaces: () => Promise.resolve([{ id: 7, name: "acme-prod", organization_id: 1, enforcement_mode: null }]),
          securityScore,
        },
      };
    });
    vi.resetModules();
    const { WidgetBody: FreshWidgetBody } = await import("./widgets");
    const { renderWithWorkspace: freshRender } = await import("@/test/render-with-workspace");

    freshRender(<FreshWidgetBody entry={{ widget_id: "security_score", data: baseScore() }} />);

    const select = (await screen.findByLabelText("Scope")) as HTMLSelectElement;
    expect(select.value).toBe("workspace:7");
    expect(screen.getByRole("option", { name: "This workspace (acme-prod)" })).toBeDefined();
    // The default (active-workspace) view reuses the batched widget-data
    // payload -- no separate GET /api/dashboard/security-score call.
    expect(securityScore).not.toHaveBeenCalled();

    vi.doUnmock("@/lib/api");
  });

  it("fetches the true full-org score only when explicitly chosen, since a workspace is active", async () => {
    const securityScore = vi.fn().mockResolvedValue(baseScore());
    vi.doMock("@/lib/api", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/lib/api")>();
      return {
        ...actual,
        api: {
          ...actual.api,
          targets: () => Promise.resolve([]),
          groups: () => Promise.resolve([]),
          workspaces: () => Promise.resolve([{ id: 7, name: "acme-prod", organization_id: 1, enforcement_mode: null }]),
          securityScore,
        },
      };
    });
    vi.resetModules();
    const { WidgetBody: FreshWidgetBody } = await import("./widgets");
    const { renderWithWorkspace: freshRender } = await import("@/test/render-with-workspace");

    freshRender(<FreshWidgetBody entry={{ widget_id: "security_score", data: baseScore() }} />);

    const select = (await screen.findByLabelText("Scope")) as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "org" } });

    await screen.findByRole("img", { name: /Security score/ });
    expect(securityScore).toHaveBeenCalledWith({});

    vi.doUnmock("@/lib/api");
  });
});

describe("Security Score widget - multi-select repositories", () => {
  it("scores nothing, without a request, until at least one repo is picked", async () => {
    const securityScore = vi.fn();
    vi.doMock("@/lib/api", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/lib/api")>();
      return {
        ...actual,
        api: {
          ...actual.api,
          targets: () => Promise.resolve([{ id: 1, name: "repo-a" }, { id: 2, name: "repo-b" }]),
          groups: () => Promise.resolve([]),
          workspaces: () => Promise.resolve([]),
          securityScore,
        },
      };
    });
    vi.resetModules();
    const { WidgetBody: FreshWidgetBody } = await import("./widgets");
    const { renderWithWorkspace: freshRender } = await import("@/test/render-with-workspace");

    freshRender(<FreshWidgetBody entry={{ widget_id: "security_score", data: baseScore() }} />);

    fireEvent.change(await screen.findByLabelText("Scope"), { target: { value: "targets" } });

    expect(await screen.findByText("No targets in scope.")).toBeDefined();
    expect(securityScore).not.toHaveBeenCalled();

    vi.doUnmock("@/lib/api");
  });

  it("sends every selected repo id once repos are picked", async () => {
    const securityScore = vi.fn().mockResolvedValue(baseScore());
    vi.doMock("@/lib/api", async (importOriginal) => {
      const actual = await importOriginal<typeof import("@/lib/api")>();
      return {
        ...actual,
        api: {
          ...actual.api,
          targets: () => Promise.resolve([{ id: 1, name: "repo-a" }, { id: 2, name: "repo-b" }]),
          groups: () => Promise.resolve([]),
          workspaces: () => Promise.resolve([]),
          securityScore,
        },
      };
    });
    vi.resetModules();
    const { WidgetBody: FreshWidgetBody } = await import("./widgets");
    const { renderWithWorkspace: freshRender } = await import("@/test/render-with-workspace");

    freshRender(<FreshWidgetBody entry={{ widget_id: "security_score", data: baseScore() }} />);

    fireEvent.change(await screen.findByLabelText("Scope"), { target: { value: "targets" } });
    const picker = (await screen.findByLabelText(
      /Repositories \(all workspaces, Cmd\/Ctrl-click for multiple\)/,
    )) as HTMLSelectElement;

    Array.from(picker.options).forEach((o) => {
      o.selected = o.value === "1" || o.value === "2";
    });
    fireEvent.change(picker);

    await screen.findByRole("img", { name: /Security score/ });
    expect(securityScore).toHaveBeenCalledWith({ targetIds: [1, 2] });

    vi.doUnmock("@/lib/api");
  });
});

describe("Security Score widget - unmeasurable components", () => {
  it("renders a component with no measurable value as unknown, never as zero", () => {
    const score = baseScore();
    // SecurityScoreComponent types `score` as a plain number, so there is no
    // way to spell "unknown" in the type; this is what the payload looks like
    // when the backend could not measure the component (no prior window to
    // compare a trend against, for instance).
    (score.components.trend as unknown as { score: number | null }).score = null;

    renderScore(score);

    const trend = row("trend");
    const text = trend.textContent ?? "";
    expect(text).toContain("Trend (7d) score");
    expect(text).toContain("Not yet measurable");

    // No confident zero anywhere in the row: no "0/100" reading, and no meter
    // drawing a zero-length bar that claims a measured value.
    expect(text).not.toContain("/100");
    expect(trend.querySelector('[role="progressbar"]')).toBeNull();
    expect(figureText("trend")).toBe("—");

    // The measurable rows are untouched and keep their meters, and the mixed
    // row still occupies the same tracks.
    const findings = row("findings");
    expect(findings.querySelector('[role="progressbar"]')).not.toBeNull();
    expect(figureText("findings")).toBe("61/100");
    expect(trend.children.length).toBe(findings.children.length);
  });

  it("honours an explicit unmeasurable flag, not only a missing score", () => {
    const score = baseScore();
    // The other shape the score API could grow: the number is present but
    // meaningless, and the component says so.
    Object.assign(score.components.trend, { measurable: false, score: 0 });

    renderScore(score);

    const text = row("trend").textContent ?? "";
    expect(text).toContain("Not yet measurable");
    expect(text).not.toContain("0/100");
    expect(figureText("trend")).toBe("—");
  });
});
