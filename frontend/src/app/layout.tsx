import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "OSP - DevSecOps Vulnerability Management",
  description: "Open-source vulnerability management platform",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-neutral-950 text-neutral-100">
        <header className="border-b border-neutral-800 px-6 py-4 flex items-center gap-6">
          <span className="font-semibold tracking-tight">OSP</span>
          <nav className="flex gap-4 text-sm text-neutral-400">
            <Link href="/" className="hover:text-white">Posture</Link>
            <Link href="/targets" className="hover:text-white">Targets</Link>
            <Link href="/findings" className="hover:text-white">Findings</Link>
          </nav>
        </header>
        <main className="flex-1 px-6 py-8 max-w-6xl w-full mx-auto">{children}</main>
      </body>
    </html>
  );
}
