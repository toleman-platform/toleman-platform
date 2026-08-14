import type { Metadata } from "next";
import { cookies } from "next/headers";
import { Plus_Jakarta_Sans, Geist_Mono } from "next/font/google";
import { DensityInit } from "@/components/density-toggle";
import { ThemeInit, THEME_COOKIE_KEY } from "@/components/theme-toggle";
import "./globals.css";

// Plus Jakarta Sans: distinctive geometric grotesque, used everywhere in the
// UI (body copy, headings) in place of the previous system-default Geist —
// part of #77's typography pass. Weight range covers body copy through
// display headings so we don't need a second display font.
const displaySans = Plus_Jakarta_Sans({
  variable: "--font-display-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Rikugan - DevSecOps Vulnerability Management",
  description: "Open-source vulnerability management platform",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // Theme (#115): read the persisted preference straight from the request's
  // cookie (set alongside localStorage by ThemeToggle, see
  // src/components/theme-toggle.tsx) so the server can render the correct
  // `data-theme` attribute in the initial HTML -- no flash of the wrong
  // theme on load, since there's nothing client-side to correct after the
  // fact. `ThemeInit` is just a same-tab safety net for the cookie/
  // localStorage falling out of sync (see its own comment).
  const cookieStore = await cookies();
  const theme = cookieStore.get(THEME_COOKIE_KEY)?.value === "light" ? "light" : undefined;

  return (
    <html
      lang="en"
      data-theme={theme}
      className={`${displaySans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-background text-foreground">
        <DensityInit />
        <ThemeInit />
        {children}
      </body>
    </html>
  );
}
