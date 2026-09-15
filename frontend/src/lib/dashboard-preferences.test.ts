import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WidgetId } from "@/types";
import {
  clearWidgetVisibility,
  defaultWidgetsForRole,
  readWidgetVisibility,
  resolveHiddenWidgets,
  widgetVisibilityStorageKey,
  writeWidgetVisibility,
} from "./dashboard-preferences";

// The widget set the backend hands a user who has never saved a layout
// (app.core.widgets.DEFAULT_WIDGET_ORDER), in that order, plus the
// pull-request widget an engineer would add. Role defaults are only ever
// applied to widgets that are actually in a layout, so this is the realistic
// input to test them against.
const STOCK_LAYOUT: WidgetId[] = [
  "security_score",
  "kpi_cards",
  "sla_compliance",
  "findings_trend",
  "top_risky_repos",
  "cve_timeline",
  "recent_findings",
  "guardrail_activity",
];

function visible(role: string | null, layout: WidgetId[] = STOCK_LAYOUT): WidgetId[] {
  const hidden = resolveHiddenWidgets(null, role, layout);
  return layout.filter((id) => !hidden.has(id));
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("role defaults", () => {
  it("gives a leadership role posture and trend, not someone else's work queue", () => {
    const shown = visible("admin");
    expect(shown).toContain("security_score");
    expect(shown).toContain("kpi_cards");
    expect(shown).toContain("findings_trend");
    expect(shown).toContain("sla_compliance");
    expect(shown).not.toContain("recent_findings");
    expect(shown).not.toContain("guardrail_activity");
    // Posture leads the page: the first card an admin sees is the score.
    expect(shown[0]).toBe("security_score");
  });

  it("gives an engineer the queue and what is blocking merges, not the reporting cards", () => {
    const shown = visible("developer");
    expect(shown).toContain("recent_findings");
    expect(shown).toContain("guardrail_activity");
    expect(shown).not.toContain("security_score");
    expect(shown).not.toContain("kpi_cards");
    expect(shown).not.toContain("sla_compliance");
    // Work leads the page: the first card an engineer sees is their queue.
    expect(shown[0]).toBe("recent_findings");
  });

  it("gives the two roles genuinely different dashboards", () => {
    expect(visible("admin")).not.toEqual(visible("developer"));
    expect(defaultWidgetsForRole("admin")).not.toEqual(defaultWidgetsForRole("developer"));
  });

  it("treats security_engineer as leadership and viewer as an overview", () => {
    expect(visible("security_engineer")).toEqual(visible("admin"));
    const overview = visible("viewer");
    expect(overview).toContain("security_score");
    expect(overview).toContain("recent_findings");
    expect(overview).not.toContain("cve_timeline");
  });

  it("hides nothing when the role is unknown or unreadable", () => {
    expect(defaultWidgetsForRole(null)).toBeNull();
    expect(defaultWidgetsForRole("chief_of_vibes")).toBeNull();
    expect(visible(null)).toEqual(STOCK_LAYOUT);
    expect(visible("chief_of_vibes")).toEqual(STOCK_LAYOUT);
  });

  it("shows everything rather than nothing when a role default matches no widget in the layout", () => {
    // An engineer whose layout happens to hold only reporting widgets: the
    // default would hide all of them, and an empty page tells them less than
    // the wrong widgets do.
    const reportingOnly: WidgetId[] = ["security_score", "kpi_cards"];
    expect(visible("developer", reportingOnly)).toEqual(reportingOnly);
  });
});

describe("stored preference", () => {
  it("wins over the role default, in both directions", () => {
    // An admin who turned the posture card off and the queue on.
    const hidden = resolveHiddenWidgets({ hidden: ["kpi_cards"] }, "admin", STOCK_LAYOUT);
    expect(hidden.has("kpi_cards")).toBe(true);
    expect(hidden.has("recent_findings")).toBe(false);
  });

  it("is honoured even when it hides everything, unlike a role default", () => {
    const hidden = resolveHiddenWidgets({ hidden: STOCK_LAYOUT }, "admin", STOCK_LAYOUT);
    expect(hidden.size).toBe(STOCK_LAYOUT.length);
  });

  it("ignores stored ids that are not in the layout", () => {
    const hidden = resolveHiddenWidgets({ hidden: ["ai_ml_risk"] }, "admin", ["kpi_cards"]);
    expect(hidden.size).toBe(0);
  });

  it("round-trips a write through storage, keyed by user id", () => {
    expect(writeWidgetVisibility(7, ["sla_compliance", "cve_timeline"])).toBe(true);

    const snapshot = readWidgetVisibility(7);
    expect(snapshot.storageReadable).toBe(true);
    expect(snapshot.preference?.hidden).toEqual(["sla_compliance", "cve_timeline"]);

    // Another user on the same browser is unaffected.
    expect(readWidgetVisibility(8).preference).toBeNull();
    expect(window.localStorage.getItem(widgetVisibilityStorageKey(8))).toBeNull();
  });

  it("returns the same object for repeated reads so a store subscription cannot loop", () => {
    writeWidgetVisibility(7, ["sla_compliance"]);
    expect(readWidgetVisibility(7)).toBe(readWidgetVisibility(7));
  });

  it("forgets the preference on clear, so the role default applies again", () => {
    writeWidgetVisibility(7, ["kpi_cards"]);
    expect(clearWidgetVisibility(7)).toBe(true);
    expect(readWidgetVisibility(7).preference).toBeNull();
  });

  it("drops ids it cannot render rather than keeping them forever", () => {
    window.localStorage.setItem(
      widgetVisibilityStorageKey(7),
      JSON.stringify({ hidden: ["kpi_cards", "widget_from_2019", 42, null] }),
    );
    expect(readWidgetVisibility(7).preference?.hidden).toEqual(["kpi_cards"]);
  });

  it("treats an unparseable value as no preference at all", () => {
    window.localStorage.setItem(widgetVisibilityStorageKey(7), "{not json");
    const snapshot = readWidgetVisibility(7);
    expect(snapshot.preference).toBeNull();
    // Not a storage failure: storage answered, it just held nothing usable.
    expect(snapshot.storageReadable).toBe(true);
  });
});

describe("storage the browser will not hand over", () => {
  it("reports the read as failed instead of throwing, and offers no preference", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });

    const snapshot = readWidgetVisibility(7);
    expect(snapshot.storageReadable).toBe(false);
    expect(snapshot.preference).toBeNull();
    // Which means the role default still decides, and still leaves a
    // dashboard on screen.
    expect(resolveHiddenWidgets(snapshot.preference, "developer", STOCK_LAYOUT).size).toBeLessThan(
      STOCK_LAYOUT.length,
    );
  });

  it("reports a failed write instead of pretending the choice was remembered", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("quota", "QuotaExceededError");
    });
    expect(writeWidgetVisibility(7, ["kpi_cards"])).toBe(false);
  });

  it("stores nothing when the user is unknown", () => {
    expect(writeWidgetVisibility(null, ["kpi_cards"])).toBe(false);
    expect(clearWidgetVisibility(null)).toBe(false);
    expect(readWidgetVisibility(null).preference).toBeNull();
    expect(window.localStorage.length).toBe(0);
  });
});
