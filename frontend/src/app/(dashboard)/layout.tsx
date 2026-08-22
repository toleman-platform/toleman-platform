import { cookies } from "next/headers";
import { Sidebar } from "@/components/sidebar";
import { AuthUser, fetchWithConnectionRetry } from "@/lib/api";
// Plain module, not theme-toggle.tsx -- see @/lib/theme for why a Server
// Component must not import these from a "use client" file.
import { THEME_COOKIE_KEY, type Theme } from "@/lib/theme";

// See the matching comment in src/lib/api.ts -- API_INTERNAL_URL lets the
// Next.js server (inside the frontend container) reach the backend over the
// docker-compose network, independent of the build-time, browser-facing
// NEXT_PUBLIC_API_URL.
const API_URL = process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function getCurrentUser(): Promise<AuthUser | null> {
  const cookieStore = await cookies();
  const session = cookieStore.get("rikugan_session");
  if (!session) return null;
  // (#235, UI-03) This layout wraps every dashboard page, so an uncaught
  // failure here used to blank the entire app -- a routine backend restart
  // (a few seconds of connection-refused while the new container starts)
  // rendered as Next's generic "This page couldn't load", with nothing on
  // screen saying why. fetchWithConnectionRetry absorbs the brief, common
  // case (see its own comment in lib/api.ts); the try/catch below is the
  // backstop for whatever the retries don't cover. Falling back to `null`
  // treats "can't reach the backend" the same as "not logged in" --
  // Sidebar's own missing-user state is a far better failure mode than a
  // blank crash, and is what the person actually sees a moment later once
  // the retry-driven client-side fetches on the page itself resolve or the
  // backend comes back and a reload picks the session back up.
  let res: Response;
  try {
    res = await fetchWithConnectionRetry(`${API_URL}/api/auth/me`, {
      headers: { Cookie: `rikugan_session=${session.value}` },
      cache: "no-store",
    });
  } catch {
    return null;
  }
  if (!res.ok) return null;
  return res.json();
}

async function getInitialTheme(): Promise<Theme> {
  const cookieStore = await cookies();
  return cookieStore.get(THEME_COOKIE_KEY)?.value === "light" ? "light" : "dark";
}

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();
  const initialTheme = await getInitialTheme();

  return (
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
  );
}
