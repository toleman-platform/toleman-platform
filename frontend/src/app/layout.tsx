import type { Metadata } from "next";
import { Plus_Jakarta_Sans, Geist_Mono } from "next/font/google";
import { DensityInit } from "@/components/density-toggle";
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

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${displaySans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-background text-foreground">
        <DensityInit />
        {children}
      </body>
    </html>
  );
}
