import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { Sidebar } from "@/components/sidebar";
import { AuthUser, Target } from "@/lib/api";

// See the matching comment in src/lib/api.ts -- API_INTERNAL_URL lets the
// Next.js server (inside the frontend container) reach the backend over the
// docker-compose network, independent of the build-time, browser-facing
// NEXT_PUBLIC_API_URL.
const API_URL = process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const ONBOARDING_EXEMPT_PATHS = ["/onboarding", "/settings", "/admin"];

async function getCurrentUser(): Promise<AuthUser | null> {
  const cookieStore = await cookies();
  const session = cookieStore.get("osp_session");
  if (!session) return null;
  const res = await fetch(`${API_URL}/api/auth/me`, {
    headers: { Cookie: `osp_session=${session.value}` },
    cache: "no-store",
  });
  if (!res.ok) return null;
  return res.json();
}

async function getTargets(): Promise<Target[]> {
  const cookieStore = await cookies();
  const session = cookieStore.get("osp_session");
  if (!session) return [];
  const res = await fetch(`${API_URL}/api/targets`, {
    headers: { Cookie: `osp_session=${session.value}` },
    cache: "no-store",
  });
  if (!res.ok) return [];
  return res.json();
}

async function getCurrentPath(): Promise<string> {
  const headerStore = await headers();
  return headerStore.get("x-pathname") || "";
}

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();

  if (user) {
    const pathname = await getCurrentPath();
    const isExempt = ONBOARDING_EXEMPT_PATHS.some((p) => pathname.startsWith(p));
    if (!isExempt) {
      const targets = await getTargets();
      if (targets.length === 0) {
        redirect("/onboarding");
      }
    }
  }

  return (
    <div className="flex h-screen w-full overflow-hidden">
      <Sidebar user={user} />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl px-6 py-8">{children}</div>
      </main>
    </div>
  );
}
