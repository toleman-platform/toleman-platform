import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { Sidebar } from "./sidebar";
import type { AuthUser } from "@/lib/api";

const { buildInfo, logout } = vi.hoisted(() => ({
  buildInfo: vi.fn(),
  logout: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { buildInfo, logout },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
}));

// The search palette, the density/theme controls and the brand mark all sit
// outside the navigation list under test. Stubbing them keeps the only
// anchors in the rendered tree the nav's own, so an href assertion cannot be
// satisfied by a link somewhere else in the sidebar chrome.
vi.mock("@/components/global-search", () => ({ GlobalSearch: () => null }));
vi.mock("@/components/density-toggle", () => ({ DensityToggle: () => null }));
vi.mock("@/components/theme-toggle", () => ({ ThemeToggle: () => null }));
vi.mock("@/components/brand-mark", () => ({ BrandLockup: () => null }));

/**
 * Every destination the sidebar offered before the Operate group was split
 * into Audit Trails and Administration. Written out by hand rather than read
 * back off the component, so that losing one of them fails here instead of
 * letting the component quietly agree with itself.
 */
const PRE_EXISTING_HREFS = [
  "/",
  "/targets",
  "/api-discovery",
  "/scans",
  "/sbom",
  "/malicious-packages",
  "/ai-security",
  "/findings",
  "/pr-history",
  "/approval-queue",
  "/guardrails",
  "/reports",
  "/ai-analysis",
  "/audit-log",
  "/github-org-logs",
  "/settings",
  "/workspaces",
  "/admin",
];

/** The three destinations carrying `adminOnly` in the component. */
const ADMIN_ONLY_HREFS = ["/guardrails", "/workspaces", "/admin"];

function user(role: string): AuthUser {
  return { id: 1, email: "someone@example.com", name: "Some One", role };
}

function navIn(container: HTMLElement): HTMLElement {
  const nav = container.querySelector("nav");
  if (!nav) throw new Error("sidebar rendered no <nav>");
  return nav;
}

/** Hrefs in one sidebar's nav, in render order. Read fresh from the DOM on
 *  every call; never held across a re-render, where React reuses the nodes. */
function hrefsIn(container: HTMLElement): string[] {
  return Array.from(navIn(container).querySelectorAll("a")).map((a) => a.getAttribute("href") ?? "");
}

/** Each group heading paired with the hrefs rendered beneath it. */
function groupsIn(container: HTMLElement): { label: string; hrefs: string[] }[] {
  return Array.from(navIn(container).children).map((group) => ({
    label: (group.firstElementChild?.textContent ?? "").trim(),
    hrefs: Array.from(group.querySelectorAll("a")).map((a) => a.getAttribute("href") ?? ""),
  }));
}

/** The "ADMIN" markers rendered next to restricted destinations. */
function adminBadgeCount(container: HTMLElement): number {
  return Array.from(navIn(container).querySelectorAll("span")).filter(
    (el) => el.textContent?.trim() === "ADMIN"
  ).length;
}

beforeEach(() => {
  // The build stamp is not under test. A failed read is the component's own
  // no-op path (it catches and simply omits the stamp), so no state update
  // lands after the assertions below have run.
  buildInfo.mockRejectedValue(new Error("build info not under test"));
  logout.mockResolvedValue(undefined);
  // jsdom implements no matchMedia, and the sidebar reads one to auto-collapse
  // into the icon rail between 768px and 1023px. `matches: false` is the
  // expanded desktop layout, the one that renders labels and group headings.
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

describe("Sidebar navigation", () => {
  it("still offers every destination it offered before the Operate group was split", () => {
    const { container } = render(<Sidebar user={user("admin")} />);

    const hrefs = hrefsIn(container);
    const missing = PRE_EXISTING_HREFS.filter((href) => !hrefs.includes(href));
    expect(missing).toEqual([]);
  });

  it("separates the evidence trails from the configuration surfaces", () => {
    const { container } = render(<Sidebar user={user("admin")} />);

    const groups = groupsIn(container);
    expect(groups.map((g) => g.label).includes("Operate")).toBe(false);

    const auditTrails = groups.find((g) => g.label === "Audit Trails");
    expect(auditTrails?.hrefs).toEqual(["/audit-log", "/github-org-logs"]);

    const administration = groups.find((g) => g.label === "Administration");
    expect(administration?.hrefs).toEqual(["/administration", "/settings", "/workspaces", "/admin"]);
  });
});

describe("Sidebar role filtering", () => {
  it("renders no admin-only destination for a non-admin user", () => {
    const { container } = render(<Sidebar user={user("developer")} />);

    const hrefs = hrefsIn(container);
    const leaked = ADMIN_ONLY_HREFS.filter((href) => hrefs.includes(href));
    expect(leaked).toEqual([]);
    expect(adminBadgeCount(container)).toBe(0);

    // The unrestricted destinations in the same two groups still render, so
    // the assertions above cannot be satisfied by a nav that failed to render.
    expect(hrefs.includes("/audit-log")).toBe(true);
    expect(hrefs.includes("/settings")).toBe(true);
    expect(hrefs.includes("/administration")).toBe(true);
  });

  it("drops a group heading whose only destination is admin-only", () => {
    const { container } = render(<Sidebar user={user("developer")} />);

    const labels = groupsIn(container).map((g) => g.label);
    expect(labels.includes("Guardrails")).toBe(false);
    expect(labels.includes("Administration")).toBe(true);
    expect(labels.includes("Audit Trails")).toBe(true);
  });

  it("renders admin-only destinations for an admin and for a security engineer", () => {
    const admin = render(<Sidebar user={user("admin")} />);
    const adminHrefs = hrefsIn(admin.container);
    expect(adminBadgeCount(admin.container)).toBe(ADMIN_ONLY_HREFS.length);
    admin.unmount();

    const engineer = render(<Sidebar user={user("security_engineer")} />);
    const engineerHrefs = hrefsIn(engineer.container);

    const missingForAdmin = ADMIN_ONLY_HREFS.filter((href) => !adminHrefs.includes(href));
    const missingForEngineer = ADMIN_ONLY_HREFS.filter((href) => !engineerHrefs.includes(href));
    expect(missingForAdmin).toEqual([]);
    expect(missingForEngineer).toEqual([]);
  });

  it("renders no admin-only destination when there is no signed-in user", () => {
    const { container } = render(<Sidebar user={null} />);

    const hrefs = hrefsIn(container);
    const leaked = ADMIN_ONLY_HREFS.filter((href) => hrefs.includes(href));
    expect(leaked).toEqual([]);
    expect(hrefs.includes("/")).toBe(true);
  });
});
