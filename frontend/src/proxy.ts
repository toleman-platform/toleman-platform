import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const PUBLIC_PATHS = ["/login"];
const SESSION_COOKIE = "toleman_session";

// See the matching comment in src/lib/api.ts / (dashboard)/layout.tsx --
// API_INTERNAL_URL lets the Next.js server reach the backend over the
// docker-compose network; falls back to the browser-facing URL, which also
// works for local `npm run dev` where both resolve the same way.
const API_URL = process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// Issue #128: a cookie merely being *present* doesn't mean the session is
// still good -- it may be expired, or revoked server-side (token_version
// bumped by logout/password-change, possibly from another device). Treating
// presence as validity meant a stale cookie both (a) tripped the "already
// logged in, skip /login" redirect below and landed the user back on / with
// a broken half-authenticated shell, and (b) sailed through the
// protected-route gate since `hasSession` was true, so the dashboard layout
// rendered with a null user (sidebar badge "Unknown", KPI widgets throwing
// uncaught 401s) instead of ever reaching /login. The only real signal is a
// live check against the same endpoint the dashboard layout itself trusts
// (`current_user()` in backend/app/api/auth.py, which checks token_version).
async function hasValidSession(request: NextRequest): Promise<boolean> {
  const session = request.cookies.get(SESSION_COOKIE);
  if (!session) return false;
  try {
    const res = await fetch(`${API_URL}/api/auth/me`, {
      headers: { Cookie: `${SESSION_COOKIE}=${session.value}` },
      cache: "no-store",
    });
    return res.ok;
  } catch {
    // Backend unreachable -- fail closed (treat as unauthenticated) rather
    // than risk rendering the authenticated shell on a guess.
    return false;
  }
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isPublic = PUBLIC_PATHS.some((p) => pathname.startsWith(p));
  const validSession = await hasValidSession(request);

  if (!validSession && !isPublic) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    const response = NextResponse.redirect(loginUrl);
    // Clear the stale/invalid cookie so it isn't resent on every subsequent
    // request (and so it can't shadow a later, genuinely valid login).
    response.cookies.delete(SESSION_COOKIE);
    return response;
  }

  if (validSession && pathname === "/login") {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
