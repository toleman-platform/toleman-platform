"use client";

import { useState } from "react";
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
  Settings,
  UserCog,
  LogOut,
  Shield,
  ChevronLeft,
  ChevronRight,
  ScrollText,
  Github,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { api, AuthUser } from "@/lib/api";
import { GlobalSearch } from "@/components/global-search";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/targets", label: "Repo Sync", icon: GitBranch },
  { href: "/findings", label: "Vulnerabilities", icon: ShieldAlert },
  { href: "/scans", label: "On-Demand Scan", icon: Scan },
  { href: "/ai-analysis", label: "AI Analysis", icon: BrainCircuit },
  { href: "/pr-history", label: "PR History", icon: GitPullRequest },
  { href: "/api-discovery", label: "API Discovery", icon: Globe },
  { href: "/sbom", label: "SBOM & OSS Vulns", icon: Package },
];

const BOTTOM_ITEMS = [
  { href: "/settings", label: "Settings", icon: Settings, adminOnly: false },
  { href: "/audit-log", label: "Audit Log", icon: ScrollText, adminOnly: false },
  { href: "/github-org-logs", label: "GitHub Org Logs", icon: Github, adminOnly: false },
  { href: "/admin", label: "Admin", icon: UserCog, adminOnly: true },
];

export function Sidebar({ user }: { user: AuthUser | null }) {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);

  async function onLogout() {
    await api.logout().catch(() => {});
    router.push("/login");
    router.refresh();
  }

  const initials = user?.name
    ? user.name.split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase()
    : "?";

  function NavLink({ item }: { item: (typeof NAV_ITEMS)[number] }) {
    const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
    return (
      <Link
        key={item.href}
        href={item.href}
        title={collapsed ? item.label : undefined}
        className={cn(
          "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
          isActive
            ? "bg-sidebar-accent text-primary font-medium"
            : "text-sidebar-foreground hover:bg-sidebar-accent/50",
          collapsed && "justify-center px-2"
        )}
      >
        <item.icon className={cn("h-4 w-4 shrink-0", isActive && "text-primary")} />
        {!collapsed && <span>{item.label}</span>}
      </Link>
    );
  }

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-sidebar-border bg-sidebar transition-all duration-200",
        collapsed ? "w-16" : "w-60"
      )}
    >
      <div className={cn("flex h-14 items-center gap-3 border-b border-sidebar-border px-4", collapsed && "justify-center px-2")}>
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
          <Shield className="h-5 w-5" />
        </div>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="text-sm font-bold text-sidebar-foreground">OSP</span>
            <span className="text-[10px] text-muted-foreground">Security Dashboard</span>
          </div>
        )}
      </div>

      <div className={cn("border-b border-sidebar-border p-2", collapsed && "flex justify-center")}>
        <GlobalSearch collapsed={collapsed} />
      </div>

      <nav className="flex flex-1 flex-col gap-1 overflow-y-auto p-2">
        <div className={cn("mb-1 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground", collapsed && "sr-only")}>
          Main
        </div>
        {NAV_ITEMS.map((item) => (
          <NavLink key={item.href} item={item} />
        ))}
      </nav>

      <div className="flex flex-col gap-1 border-t border-sidebar-border p-2">
        {BOTTOM_ITEMS.filter(
          (item) => !item.adminOnly || user?.role === "admin" || user?.role === "security_engineer"
        ).map((item) => (
          <NavLink key={item.href} item={item} />
        ))}

        <div className={cn("mt-1 flex items-center gap-3 rounded-md border border-sidebar-border bg-sidebar-accent/30 px-3 py-2", collapsed && "justify-center px-2")}>
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-[10px] font-bold text-primary">
            {initials}
          </div>
          {!collapsed && (
            <div className="flex flex-1 flex-col overflow-hidden">
              <span className="truncate text-xs font-medium text-sidebar-foreground">{user?.name ?? "Unknown"}</span>
              <span className="truncate text-[10px] text-muted-foreground">{user?.role ?? ""}</span>
            </div>
          )}
          {!collapsed && (
            <button onClick={onLogout} title="Sign out" className="text-muted-foreground hover:text-destructive">
              <LogOut className="h-4 w-4" />
            </button>
          )}
        </div>

        <button
          onClick={() => setCollapsed((v) => !v)}
          className="mt-1 flex w-full items-center justify-center gap-2 rounded-md px-3 py-1.5 text-xs text-muted-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
