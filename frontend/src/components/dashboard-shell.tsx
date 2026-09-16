"use client";

/**
 * Client boundary for the dashboard app shell (issue #506).
 *
 * layout.tsx is a Server Component (it does a cookie-based fetch for the
 * signed-in user and the initial theme) and React context cannot be
 * provided from one -- see the "Context providers" pattern in Next's own
 * docs. This is that boundary: a thin client wrapper that owns nothing
 * itself beyond mounting WorkspaceProvider around the same Sidebar + main
 * structure layout.tsx used to render inline.
 */

import { Sidebar } from "@/components/sidebar";
import { WorkspaceProvider } from "@/contexts/workspace-context";
import { AuthUser } from "@/lib/api";
import { Theme } from "@/components/theme-toggle";

export function DashboardShell({
  user,
  initialTheme,
  children,
}: {
  user: AuthUser | null;
  initialTheme?: Theme;
  children: React.ReactNode;
}) {
  return (
    <WorkspaceProvider userId={user?.id ?? null}>
      <div className="flex h-screen w-full overflow-hidden">
        <Sidebar user={user} initialTheme={initialTheme} />
        <main className="flex-1 overflow-y-auto">
          <div
            className="mx-auto max-w-6xl px-6 pt-14 md:pt-[var(--density-page-py)]"
            style={{ paddingBottom: "var(--density-page-py)" }}
          >
            {children}
          </div>
        </main>
      </div>
    </WorkspaceProvider>
  );
}
