"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard,
  GitBranch,
  ShieldAlert,
  Scan,
  BrainCircuit,
  GitPullRequest,
  Globe,
  Package,
  FileText,
  Settings,
  UserCog,
  LogOut,
  ChevronLeft,
  ChevronRight,
  ScrollText,
  Github,
  Menu,
  X,
  ShieldCheck,
  ClipboardCheck,
  Building2,
  Bot,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { api, AuthUser, BuildInfo } from "@/lib/api";
import { GlobalSearch } from "@/components/global-search";
import { DensityToggle } from "@/components/density-toggle";
import { ThemeToggle, Theme } from "@/components/theme-toggle";
import { BrandLockup } from "@/components/brand-mark";

type NavItem = { href: string; label: string; icon: LucideIcon; adminOnly?: boolean };
type NavGroup = { label: string; items: NavItem[] };

// Regrouped by workflow stage (#116) -- the order a security engineer
// actually works a finding (discover -> scan -> triage -> report -> operate)
// instead of the old flat 13-item "MAIN" list build order.
const NAV_GROUPS: NavGroup[] = [
  {
    label: "Overview",
    items: [{ href: "/", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Discover",
    items: [
      { href: "/targets", label: "Targets", icon: GitBranch },
      { href: "/api-discovery", label: "API Discovery", icon: Globe },
    ],
  },
  {
    label: "Scan",
    items: [
      { href: "/scans", label: "On-Demand Scan", icon: Scan },
      { href: "/sbom", label: "SBOM & OSS Vulns", icon: Package },
      // IA review (#224): AI-repo detection (#185), ModelScan (#186) and
      // the LLM ruleset (#189) had no dedicated nav entry at all -- findable
      // only by already knowing to filter Findings by tool name.
      { href: "/ai-security", label: "AI Security", icon: Bot },
    ],
  },
  {
    label: "Triage",
    items: [
      // Nav label unified to "Findings" (#116) -- was "Vulnerabilities" here
      // while the page header said "Findings" and the dashboard KPI said
      // "Open Vulnerabilities"; all three now agree on one term.
      { href: "/findings", label: "Findings", icon: ShieldAlert },
      { href: "/pr-history", label: "PR History", icon: GitPullRequest },
      // IA review (#224): daily security-review work, not admin config --
      // moved out from under /admin. Deliberately NOT adminOnly: the page
      // itself already gates on admin/security_engineer, this just gives
      // security_engineer users (who could always reach it by typing the
      // old /admin URL, but had no link) an actual nav entry.
      { href: "/approval-queue", label: "Approval Queue", icon: ClipboardCheck },
    ],
  },
  {
    label: "Guardrails",
    items: [
      { href: "/guardrails", label: "Guardrails", icon: ShieldCheck, adminOnly: true },
    ],
  },
  {
    label: "Report",
    items: [
      { href: "/reports", label: "Compliance Reports", icon: FileText },
      { href: "/ai-analysis", label: "Explain with AI", icon: BrainCircuit },
    ],
  },
  {
    label: "Operate",
    items: [
      { href: "/audit-log", label: "Audit Log", icon: ScrollText },
      { href: "/github-org-logs", label: "GitHub Org Logs", icon: Github },
      { href: "/settings", label: "Settings", icon: Settings },
      // IA review (#224): workspace rename, API key and role assignment used
      // to be split between a target-picker-driven card in Settings and a
      // flat tab in Admin. Both moved into this one page.
      { href: "/workspaces", label: "Workspaces", icon: Building2, adminOnly: true },
      { href: "/admin", label: "Control Plane", icon: UserCog, adminOnly: true },
    ],
  },
];

export function Sidebar({ user, initialTheme }: { user: AuthUser | null; initialTheme?: Theme }) {
  const pathname = usePathname();
  const router = useRouter();
  // (BLD-01) Which backend is actually answering. A stale instance holding
  // the same port is otherwise indistinguishable from a fresh one -- an
  // evaluator lost an hour to exactly that.
  const [build, setBuild] = useState<BuildInfo | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .buildInfo()
      .then((b) => {
        if (!cancelled) setBuild(b);
      })
      .catch(() => {
        // Not worth surfacing -- the stamp is a diagnostic aid, and failing
        // to show it must never disturb the nav.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  // "More nav below the fold" affordance -- see the comment on the nav
  // element itself. Recomputed on scroll and on resize, since which items
  // fit depends entirely on viewport height.
  const navRef = useRef<HTMLElement | null>(null);
  const [navHasMore, setNavHasMore] = useState(false);

  const updateNavScroll = useCallback(() => {
    const el = navRef.current;
    if (!el) return;
    setNavHasMore(el.scrollHeight - el.scrollTop - el.clientHeight > 4);
  }, []);

  useEffect(() => {
    updateNavScroll();
    window.addEventListener("resize", updateNavScroll);
    return () => window.removeEventListener("resize", updateNavScroll);
  }, [updateNavScroll, collapsed, user]);

  // Responsive strategy (#116): the sidebar was previously a fixed 240px
  // desktop panel with no breakpoint handling, confirmed broken below
  // ~768px (dropdown overflow, badge/score overlap at 375px). Below
  // ~1024px it now auto-collapses to the existing icon rail; below ~768px
  // it becomes an off-canvas drawer (scrim + slide-in), reusing the same
  // `collapsed` state the manual "Collapse" toggle already drives.
  useEffect(() => {
    const tabletQuery = window.matchMedia("(min-width: 768px) and (max-width: 1023px)");
    const applyTablet = () => {
      if (tabletQuery.matches) setCollapsed(true);
    };
    applyTablet();
    tabletQuery.addEventListener("change", applyTablet);
    return () => tabletQuery.removeEventListener("change", applyTablet);
  }, []);

  // Close the mobile drawer on navigation. This is React's documented
  // "adjust state when a prop changes" pattern rather than an effect: React
  // re-runs the component immediately with the new state and never commits
  // the intermediate frame, so the drawer does not paint open-then-closed the
  // way the effect version briefly did.
  const [lastPathname, setLastPathname] = useState(pathname);
  if (lastPathname !== pathname) {
    setLastPathname(pathname);
    setMobileOpen(false);
  }

  async function onLogout() {
    await api.logout().catch(() => {});
    router.push("/login");
    router.refresh();
  }

  const initials = user?.name
    ? user.name.split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase()
    : "?";

  // True icon-rail mode: collapsed AND not the full-width mobile drawer.
  const iconRail = collapsed && !mobileOpen;

  function NavLink({ item }: { item: NavItem }) {
    const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
    return (
      <Link
        key={item.href}
        href={item.href}
        title={iconRail ? item.label : undefined}
        className={cn(
          "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
          isActive
            ? "bg-sidebar-accent text-accent-strong font-medium"
            : "text-sidebar-foreground hover:bg-sidebar-accent/50",
          iconRail && "justify-center px-2"
        )}
      >
        <item.icon className={cn("h-4 w-4 shrink-0", isActive && "text-accent-strong")} />
        {!iconRail && <span className="flex-1">{item.label}</span>}
        {!iconRail && item.adminOnly && (
          <span className="rounded border border-warning/30 bg-warning/10 px-1 py-0.5 font-mono text-[8px] tracking-wide text-warning">
            ADMIN
          </span>
        )}
      </Link>
    );
  }

  return (
    <>
      {/* Mobile hamburger trigger -- only visible below md, opens the
          off-canvas drawer. */}
      <button
        onClick={() => setMobileOpen(true)}
        aria-label="Open navigation menu"
        className="fixed left-3 top-3 z-30 flex h-9 w-9 items-center justify-center rounded-md border border-sidebar-border bg-sidebar text-sidebar-foreground shadow-sm md:hidden"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Scrim behind the open mobile drawer. */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex h-screen w-60 flex-col border-r border-sidebar-border bg-sidebar transition-transform duration-200 md:static md:z-auto md:translate-x-0 md:transition-[width]",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          collapsed ? "md:w-16" : "md:w-60"
        )}
      >
        <div className={cn("flex h-14 items-center gap-3 border-b border-sidebar-border px-4", iconRail && "justify-center px-2")}>
          {!iconRail ? (
            <div className="flex flex-1 items-center justify-between">
              <BrandLockup markSize={30} />
              <button
                onClick={() => setMobileOpen(false)}
                aria-label="Close navigation menu"
                className="text-muted-foreground hover:text-foreground md:hidden"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <BrandLockup markSize={26} className="[&>div]:hidden" />
          )}
        </div>

        <div className={cn("border-b border-sidebar-border p-2", iconRail && "flex justify-center")}>
          <GlobalSearch collapsed={iconRail} />
        </div>

        {/* The nav scrolls, but macOS overlay scrollbars stay invisible until
            you actually scroll, so on a 900px-tall viewport the list simply
            looked complete while Audit Log, GitHub Org Logs, Settings and
            Admin sat below the fold with no cue they existed (measured: 134px
            of nav hidden at 900px, 234px at 800px). The fade below is that
            missing cue -- it only shows while there's more to scroll to. */}
        <div className="relative flex min-h-0 flex-1 flex-col">
        <nav ref={navRef} onScroll={updateNavScroll} className="flex flex-1 flex-col gap-3 overflow-y-auto p-2">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter(
              (item) => !item.adminOnly || user?.role === "admin" || user?.role === "security_engineer"
            );
            if (items.length === 0) return null;
            return (
              <div key={group.label} className="flex flex-col gap-1">
                <div className={cn("mb-1 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground", iconRail && "sr-only")}>
                  {group.label}
                </div>
                {items.map((item) => (
                  <NavLink key={item.href} item={item} />
                ))}
              </div>
            );
          })}
        </nav>
          {navHasMore && (
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-sidebar to-transparent"
            />
          )}
        </div>

        <div className="flex flex-col gap-1 border-t border-sidebar-border p-2">
          <div className={cn("mt-1 flex items-center gap-3 rounded-md border border-sidebar-border bg-sidebar-accent/30 px-3 py-2", iconRail && "justify-center px-2")}>
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[10px] font-bold text-accent-strong">
              {initials}
            </div>
            {!iconRail && (
              <div className="flex flex-1 flex-col overflow-hidden">
                <span className="truncate text-xs font-medium text-sidebar-foreground">{user?.name ?? "Unknown"}</span>
                <span className="truncate text-[10px] text-muted-foreground">{user?.role ?? ""}</span>
              </div>
            )}
            {!iconRail && (
              <button onClick={onLogout} title="Sign out" className="text-muted-foreground hover:text-destructive">
                <LogOut className="h-4 w-4" />
              </button>
            )}
          </div>

          {/* Density, theme and collapse were three full-width stacked rows,
              costing ~90px of sidebar height for controls a user touches once
              a session -- height the nav list actually needs, since it
              already overflows below the fold (hence the scroll fade above).
              They now sit side by side as an icon row, with titles and
              aria-labels carrying the meaning the visible labels used to.

              The icon rail keeps them stacked: at ~64px wide it cannot fit
              three controls across. */}
          {!iconRail && build && (
            <div
              title={`${build.version}${build.commit ? ` (${build.commit})` : ""} \u2014 database ${build.database}`}
              className="mt-1 truncate px-1 text-center text-[10px] text-muted-foreground"
            >
              {build.version}
              {build.commit ? ` \u00b7 ${build.commit.slice(0, 7)}` : ""}
            </div>
          )}

          <div className={cn("mt-1 flex gap-1", iconRail ? "flex-col" : "items-center justify-center")}>
            <DensityToggle collapsed={iconRail} compact={!iconRail} />
            <ThemeToggle collapsed={iconRail} compact={!iconRail} initialTheme={initialTheme} />
            <button
              onClick={() => setCollapsed((v) => !v)}
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              className={cn(
                "hidden items-center justify-center gap-2 rounded-md text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent/50 hover:text-foreground md:flex",
                iconRail ? "w-full px-2 py-1.5" : "h-8 w-8 shrink-0"
              )}
            >
              {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
