import type { Metadata } from "next";
import { cookies } from "next/headers";
// Plus Jakarta Sans & Geist Mono: distinctive typography system, used everywhere
// in the UI in place of system defaults; part of #77's typography pass. Centralized
// in @/lib/fonts as a single source of truth.
import { sansFont, monoFont, THEME_COOKIE_KEY } from "@/tokens";
import { DensityInit } from "@/components/density-toggle";
import { ThemeInit } from "@/components/theme-toggle";
import { DEFAULT_API_URL } from "@/lib/api";
import "./globals.css";

export const metadata: Metadata = {
  title: "Toleman - DevSecOps Vulnerability Management",
  description: "Open-source vulnerability management platform",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // Theme (#115): read the persisted preference straight from the request's
  // cookie (set alongside localStorage by ThemeToggle, see
  // src/components/theme-toggle.tsx) so the server can render the correct
  // `data-theme` attribute in the initial HTML, no flash of the wrong
  // theme on load, since there's nothing client-side to correct after the
  // fact. `ThemeInit` is just a same-tab safety net for the cookie/
  // localStorage falling out of sync (see its own comment).
  const cookieStore = await cookies();
  const theme = cookieStore.get(THEME_COOKIE_KEY)?.value === "light" ? "light" : undefined;

  // Deliberately NOT NEXT_PUBLIC_-prefixed: Next.js inlines those at build
  // time even in server code, which is exactly the coupling BLD-02 is about.
  // A plain var is read fresh from the container environment on every
  // request. Falls back to the build-time inline so an image built before
  // this change, and plain `next dev`, keep working with no configuration.
  const publicApiUrl =
    process.env.PUBLIC_API_URL || process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;

  return (
    <html
      lang="en"
      data-theme={theme}
      className={`${sansFont.variable} ${monoFont.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-background text-foreground">
        {/* (BLD-02) The backend address the *browser* should call, injected
            per request so it is a runtime value rather than something baked
            into the image by `next build`. Changing PUBLIC_API_URL and
            restarting is now enough; it used to cost a full frontend rebuild.

            JSON.stringify escapes the value, and the `<` replacement closes
            the one hole that leaves: a `</script>` inside the string would
            otherwise end this tag early. The value comes from our own
            environment, not from user input, but a script-tag injection that
            is only safe because of where the data happens to come from is
            one refactor away from not being safe. */}
        <script
          dangerouslySetInnerHTML={{
            __html: `window.__TOLEMAN_API_URL__=${JSON.stringify(publicApiUrl).replace(/</g, "\\u003c")};`,
          }}
        />
        <DensityInit />
        <ThemeInit />
        {children}
      </body>
    </html>
  );
}
