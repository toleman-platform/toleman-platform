import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import AuditLogPage from "./page";

const { auditLog, auditActors, me } = vi.hoisted(() => ({
  auditLog: vi.fn(),
  auditActors: vi.fn(),
  me: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  api: { auditLog, auditActors, me },
}));

// AuditLogFilterBar, DateRangeFilter, and ActivityPagination (reached via
// AuditLogList) all read the URL through these three hooks. Same mock as
// scans-list.test.tsx -- a plain function-component render has no Next.js
// App Router above it to supply them for real.
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/audit-log",
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
}));

function noSearchParams() {
  return Promise.resolve({});
}

// AuditLogPage is an async Server Component: calling it returns a Promise of
// the element tree, not the tree itself, so it has to be awaited before
// `render` ever sees it -- `render(<AuditLogPage ... />)` would hand
// Testing Library a thenable, not JSX.
async function renderAuditLogPage() {
  const element = await AuditLogPage({ searchParams: noSearchParams() });
  render(element);
}

describe("Audit Log page - Security Log cross-link (root cause: two unlinked audit trails)", () => {
  it("tells every viewer, regardless of role, that sign-ins and permission changes live elsewhere", async () => {
    auditLog.mockResolvedValue({ items: [], total: 0 });
    auditActors.mockResolvedValue([]);
    me.mockResolvedValue({ id: 1, email: "dev@acme.com", name: "Dev", role: "developer" });

    await renderAuditLogPage();

    const banner = screen.getByText(/Sign-ins and permission changes aren't in this trail/i);
    expect(banner).not.toBeNull();
    expect(banner.closest('[role="alert"]')?.textContent).toContain("Security Log");
  });

  it("links a confirmed admin straight to the Security Log tab", async () => {
    auditLog.mockResolvedValue({ items: [], total: 0 });
    auditActors.mockResolvedValue([]);
    me.mockResolvedValue({ id: 1, email: "admin@acme.com", name: "Admin", role: "admin" });

    await renderAuditLogPage();

    const link = screen.getByRole("link", { name: "Open Security Log" }) as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("/admin?tab=security-log");
  });

  it("omits the link for a confirmed non-admin, who would only hit a 403 (GET /api/audit/security-log is admin_required)", async () => {
    auditLog.mockResolvedValue({ items: [], total: 0 });
    auditActors.mockResolvedValue([]);
    me.mockResolvedValue({ id: 2, email: "dev@acme.com", name: "Dev", role: "developer" });

    await renderAuditLogPage();

    expect(screen.queryByRole("link", { name: "Open Security Log" })).toBeNull();
  });

  it("also omits the link when the viewer's role can't be determined -- unmeasured must not render as permitted", async () => {
    auditLog.mockResolvedValue({ items: [], total: 0 });
    auditActors.mockResolvedValue([]);
    me.mockRejectedValue(new Error("network error"));

    await renderAuditLogPage();

    // The page itself must still render -- a failed /api/auth/me is
    // secondary to the audit feed, same settleOrNull degradation as the
    // actor list a few lines above it in page.tsx.
    expect(screen.getByText(/Sign-ins and permission changes aren't in this trail/i)).not.toBeNull();
    expect(screen.queryByRole("link", { name: "Open Security Log" })).toBeNull();
  });

  it("states its own scope accurately, including the MCP/API token events the event-type facet already exposes", async () => {
    auditLog.mockResolvedValue({ items: [], total: 3 });
    auditActors.mockResolvedValue([]);
    me.mockResolvedValue({ id: 1, email: "admin@acme.com", name: "Admin", role: "admin" });

    await renderAuditLogPage();

    expect(screen.getByText(/triage decision, scan run, and MCP\/API token action/i)).not.toBeNull();
  });
});
