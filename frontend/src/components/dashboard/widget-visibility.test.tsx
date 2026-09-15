import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { DashboardBoard } from "./dashboard-board";
import type { LayoutWidget, WidgetCatalogEntry } from "@/lib/api";

// A layout covering both readings of this page: the reporting cards and the
// work cards. `security_score` is deliberately left out -- that widget makes
// its own client fetches when it has data, and none of this is about it.
const LAYOUT: LayoutWidget[] = [
  { id: "w-kpi", widget_id: "kpi_cards", config: {} },
  { id: "w-sla", widget_id: "sla_compliance", config: {} },
  { id: "w-trend", widget_id: "findings_trend", config: {} },
  { id: "w-repos", widget_id: "top_risky_repos", config: {} },
  { id: "w-queue", widget_id: "recent_findings", config: {} },
  { id: "w-guardrail", widget_id: "guardrail_activity", config: {} },
];

const CATALOG: WidgetCatalogEntry[] = [
  { widget_id: "kpi_cards", name: "Security Posture", description: "KPIs" },
];

const STORAGE_KEY_USER_7 = "toleman-dashboard-widgets:7";

function renderBoard({
  role,
  userId = 7,
  profileFailed = false,
  widgets = LAYOUT,
  catalog = CATALOG,
}: {
  role: string | null;
  userId?: number | null;
  profileFailed?: boolean;
  widgets?: LayoutWidget[];
  catalog?: WidgetCatalogEntry[];
}) {
  return render(
    <DashboardBoard
      initialWidgets={widgets}
      catalog={catalog}
      initialData={{ widgets: {} }}
      layoutFailed={false}
      catalogFailed={false}
      dataFailed={false}
      userId={userId}
      role={role}
      profileFailed={profileFailed}
    />,
  );
}

/**
 * Widget card titles currently on the page, in the order they appear. Read
 * off the rendered DOM rather than checked against a list this file already
 * holds, so "which widget leads the page" is a real assertion.
 */
function cardTitles(): string[] {
  return Array.from(document.querySelectorAll('[data-slot="card-title"]')).map((el) => el.textContent ?? "");
}

function openWidgetMenu() {
  fireEvent.click(screen.getByRole("button", { name: /Widgets/ }));
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("per-role default widget set", () => {
  it("starts a leadership account on posture and trend", () => {
    renderBoard({ role: "admin" });

    expect(screen.queryByText("Security Posture")).not.toBeNull();
    expect(screen.queryByText("Findings Over Time")).not.toBeNull();
    expect(screen.queryByText("SLA Compliance")).not.toBeNull();
    expect(screen.queryByText("Needs Action Queue")).toBeNull();
    expect(screen.queryByText("Guardrail Activity")).toBeNull();
  });

  it("starts an engineer account on their queue and what is blocking merges", () => {
    renderBoard({ role: "developer" });

    expect(screen.queryByText("Needs Action Queue")).not.toBeNull();
    expect(screen.queryByText("Guardrail Activity")).not.toBeNull();
    // SLA compliance is the reporting view and the only thing this default
    // drops. Everything else stays: a role is a guess about emphasis, and a
    // guess must never be the reason most of the dashboard is missing.
    expect(screen.queryByText("SLA Compliance")).toBeNull();
    expect(screen.queryByText("Security Posture")).not.toBeNull();
    expect(cardTitles().length).toBe(LAYOUT.length - 1);
  });

  it("gives the two roles different boards from the same saved layout", () => {
    renderBoard({ role: "admin" });
    const leadershipView = cardTitles().join("|");
    cleanup();

    renderBoard({ role: "developer" });
    const engineerView = cardTitles().join("|");

    expect(leadershipView).not.toBe(engineerView);
    expect(leadershipView.length).toBeGreaterThan(0);
    expect(engineerView.length).toBeGreaterThan(0);
  });

  it("says how much of the dashboard is being shown rather than implying it is all of it", () => {
    renderBoard({ role: "admin" });
    expect(screen.getByRole("button", { name: /Widgets/ }).textContent).toContain("4 of 6");
  });

  it("shows every widget when the role could not be read, and says why", () => {
    renderBoard({ role: null, userId: null, profileFailed: true });

    expect(cardTitles().length).toBe(6);
    expect(screen.queryByText("Your profile")).not.toBeNull();
  });
});

describe("turning widgets on and off", () => {
  it("remembers the change and re-reads it on a later visit", () => {
    renderBoard({ role: "admin" });
    expect(screen.queryByText("SLA Compliance")).not.toBeNull();

    openWidgetMenu();
    fireEvent.click(screen.getByRole("checkbox", { name: "SLA Compliance" }));
    // Close first: an open menu lists every widget by name, card or no card.
    openWidgetMenu();

    expect(screen.queryByText("SLA Compliance")).toBeNull();
    expect(screen.queryByText("Security Posture")).not.toBeNull();
    expect(screen.getByRole("button", { name: /Widgets/ }).textContent).toContain("3 of 6");

    const stored = window.localStorage.getItem(STORAGE_KEY_USER_7);
    expect(stored).not.toBeNull();
    expect(JSON.parse(stored as string).hidden).toContain("sla_compliance");

    // A fresh visit: same browser, same user, nothing carried over in memory.
    cleanup();
    renderBoard({ role: "admin" });

    expect(screen.queryByText("SLA Compliance")).toBeNull();
    expect(screen.queryByText("Security Posture")).not.toBeNull();
  });

  it("records the visibility choice when a widget is added, rather than exempting it every render", () => {
    // The first version of this fix compared against the immutable
    // initialWidgets prop at render time. That exemption re-applied on every
    // later render, so the checkbox could never hide the widget during the
    // visit, and because nothing was stored a reload handed it straight back
    // to the role default. The choice has to be recorded when it is made.
    const catalog = [
      ...CATALOG,
      { widget_id: "security_score" as const, name: "Security Score", description: "Posture" },
    ];
    renderBoard({ role: "developer", catalog });

    fireEvent.click(screen.getByRole("button", { name: /Edit Dashboard/ }));
    fireEvent.click(screen.getByRole("button", { name: /Add widget/i }));
    fireEvent.click(screen.getByRole("button", { name: /Security Score/ }));

    const stored = window.localStorage.getItem(STORAGE_KEY_USER_7);
    expect(stored).not.toBeNull();
    expect(JSON.parse(stored!).hidden).not.toContain("security_score");
  });

  it("can still hide a widget that a previous visit added", () => {
    // The other half of the same defect: once added, the widget must behave
    // like any other -- a render-time exemption made it permanently
    // unhideable.
    renderBoard({
      role: "developer",
      widgets: [...LAYOUT, { id: "w-score", widget_id: "security_score", config: {} }],
    });
    expect(screen.queryByText("Security Score")).not.toBeNull();

    openWidgetMenu();
    fireEvent.click(screen.getByRole("checkbox", { name: "Security Score" }));
    openWidgetMenu();

    expect(screen.queryByText("Security Score")).toBeNull();
  });

  it("turns a widget the role default hid back on, and keeps it on", () => {
    renderBoard({ role: "admin" });
    expect(screen.queryByText("Needs Action Queue")).toBeNull();

    openWidgetMenu();
    fireEvent.click(screen.getByRole("checkbox", { name: "Needs Action Queue" }));
    openWidgetMenu();

    expect(screen.queryByText("Needs Action Queue")).not.toBeNull();

    cleanup();
    renderBoard({ role: "admin" });
    expect(screen.queryByText("Needs Action Queue")).not.toBeNull();
  });

  it("offers a way back to the default set", () => {
    window.localStorage.setItem(
      STORAGE_KEY_USER_7,
      JSON.stringify({ hidden: LAYOUT.map((w) => w.widget_id) }),
    );
    renderBoard({ role: "admin" });

    // Not "your dashboard is empty" -- the widgets are there, they are off.
    expect(screen.queryByText("Every widget is turned off")).not.toBeNull();
    expect(screen.queryByText("Your dashboard is empty")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Reset to default" }));

    expect(screen.queryByText("Every widget is turned off")).toBeNull();
    expect(screen.queryByText("Security Posture")).not.toBeNull();
    expect(window.localStorage.getItem(STORAGE_KEY_USER_7)).toBeNull();
  });

  it("keeps hidden widgets visible and marked while the layout is being edited", () => {
    renderBoard({ role: "developer" });
    expect(screen.queryByText("SLA Compliance")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /Edit Dashboard/ }));

    // Everything the layout holds is reachable while rearranging it, and the
    // ones that will not be on the page afterwards say so.
    expect(screen.queryByText("SLA Compliance")).not.toBeNull();
    expect(screen.queryAllByText("Hidden").length).toBe(1);
  });
});

describe("a browser that will not hand over storage", () => {
  it("falls back to the role default instead of an empty dashboard", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });

    renderBoard({ role: "developer" });

    // The role default still decides, and still leaves a usable dashboard:
    // everything the layout holds except the one reporting card.
    expect(cardTitles()).toEqual([
      "Security Posture",
      "Findings Over Time",
      "Top Risky Repos",
      "Needs Action Queue",
      "Guardrail Activity",
    ]);
    expect(screen.queryByText("Every widget is turned off")).toBeNull();
    expect(screen.queryByText("Your dashboard is empty")).toBeNull();
  });

  it("does not claim a change will be remembered when it cannot be", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });

    renderBoard({ role: "developer" });
    openWidgetMenu();

    expect(screen.queryByText(/apply to this visit only/)).not.toBeNull();

    // The toggle still works for the current visit.
    fireEvent.click(screen.getByRole("checkbox", { name: "Guardrail Activity" }));
    openWidgetMenu();
    expect(screen.queryByText("Guardrail Activity")).toBeNull();
    expect(screen.queryByText("Needs Action Queue")).not.toBeNull();
  });
});
