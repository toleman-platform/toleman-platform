"use client";

import { useEffect, useRef, useState, useMemo, useCallback, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";
import {
  Search,
  GitBranch,
  X,
  Scan,
  Package,
  Bug,
  Bot,
  GitPullRequest,
  ClipboardCheck,
  ShieldCheck,
  FileText,
  BrainCircuit,
  ScrollText,
  Github,
  Settings,
  Building2,
  UserCog,
  Palette,
  Sun,
  Rows3,
  ArrowRight,
  Command,
  FileCode,
} from "lucide-react";
import { api, SearchResults } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { SeverityChip } from "@/components/ui/severity-chip";
import { Icon as IconWrapper } from "@/components/ui/icon";
import { cn } from "@/lib/utils";
import { toggleTheme } from "@/components/theme-toggle";
import { toggleDensity } from "@/components/density-toggle";

interface PaletteItem {
  id: string;
  category: "PAGES" | "ACTIONS" | "TARGETS" | "FINDINGS";
  title: string;
  subtitle?: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: React.ReactNode;
  onSelect: () => void;
}

const STATIC_PAGES = [
  { href: "/findings", title: "All Findings", subtitle: "Triage security findings & vulnerabilities", icon: ShieldCheck, keywords: "vulnerabilities cve bugs triage" },
  { href: "/targets", title: "Targets & Repositories", subtitle: "Monitored assets and repository pipelines", icon: GitBranch, keywords: "repos targets codebases projects" },
  { href: "/scans", title: "On-Demand Scans", subtitle: "Run and inspect security scan jobs", icon: Scan, keywords: "scans tools semgrep trivy gitleaks run" },
  { href: "/sbom", title: "SBOM & OSS Dependencies", subtitle: "Software bill of materials and packages", icon: Package, keywords: "sbom packages dependencies open-source osv" },
  { href: "/malicious-packages", title: "Malicious Packages", subtitle: "OpenSSF flagged malware packages", icon: Bug, keywords: "malware malicious supply chain attack" },
  { href: "/ai-security", title: "AI Security & Models", subtitle: "ModelScan & LLM ruleset findings", icon: Bot, keywords: "ai ml models huggingface modelscan" },
  { href: "/pr-history", title: "PR Guardrail History", subtitle: "Pull request scans and commit checks", icon: GitPullRequest, keywords: "pr pull requests git diff branches" },
  { href: "/approval-queue", title: "Approval Queue", subtitle: "Pending ignore requests and exceptions", icon: ClipboardCheck, keywords: "approvals triage review ignore suppress" },
  { href: "/guardrails", title: "Guardrails Policy", subtitle: "Branch blocking and compliance rules", icon: ShieldCheck, keywords: "guardrails policies blocking rules" },
  { href: "/reports", title: "Compliance Reports", subtitle: "SOC2, ISO27001, Executive exports", icon: FileText, keywords: "reports compliance export csv pdf executive" },
  { href: "/ai-analysis", title: "Explain with AI", subtitle: "Automated vulnerability risk explanations", icon: BrainCircuit, keywords: "ai explanation claude gpt summarize" },
  { href: "/audit-log", title: "Audit Trail", subtitle: "User action and system security logs", icon: ScrollText, keywords: "audit logs activity history events" },
  { href: "/github-org-logs", title: "GitHub Org Logs", subtitle: "Organization webhook and sync events", icon: Github, keywords: "github org sync webhooks events" },
  { href: "/workspaces", title: "Workspaces", subtitle: "Multi-tenant workspace configuration", icon: Building2, keywords: "workspaces tenants organizations" },
  { href: "/admin", title: "Control Plane / Admin", subtitle: "Tool registry, Celery workers & health", icon: UserCog, keywords: "admin celery workers tools health status" },
  { href: "/design-system", title: "Design System Gallery", subtitle: "Typography, color tokens, and components", icon: Palette, keywords: "design system tokens colors typography gallery" },
  { href: "/settings", title: "User Settings", subtitle: "Preferences, profile, and notifications", icon: Settings, keywords: "settings user preferences profile theme" },
];

const emptySubscribe = () => () => {};
function useIsClient() {
  return useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false
  );
}

/**
 * Enterprise Command Palette (Cmd/Ctrl+K) and sidebar search trigger.
 * Searches findings (title/file_path/rule_id/cve_id), targets (name/repo_url),
 * pages, and quick system actions via GET /api/search and client index.
 * Supports full keyboard arrow navigation, multi-source results, and theme/density toggles.
 */
export function GlobalSearch({ collapsed }: { collapsed?: boolean }) {
  const router = useRouter();
  const isClient = useIsClient();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Debounce the query, then declare it as the fetch dependency: the request
  // fires once typing settles, and useAsyncData's abort/request-id handling
  // covers the case where an earlier search resolves after a later one; the
  // hand-rolled version had no such guard, so a slow "sq" could land after a
  // fast "sqli" and show the wrong results.
  const debouncedQuery = useDebouncedValue(query.trim(), 200);
  const { data: searchData, isInitialLoading: loading } = useAsyncData<SearchResults>(
    () => api.search(debouncedQuery),
    { enabled: debouncedQuery.length > 0, deps: [debouncedQuery] },
  );

  // Gated on the live query, not the debounced one: clearing the box must
  // drop the old results immediately rather than leaving them sitting under
  // an empty input for the debounce interval.
  const apiResults = query.trim() ? searchData : null;

  // Global Cmd+K / Ctrl+K listener
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === "Escape" && open) {
        setOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  // Wait a tick for the overlay to mount before focusing.
  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => inputRef.current?.focus(), 0);
    return () => clearTimeout(t);
  }, [open]);

  const navigate = useCallback((href: string) => {
    setOpen(false);
    router.push(href);
  }, [router]);

  function handleThemeClick() {
    toggleTheme();
    setOpen(false);
  }

  function handleDensityClick() {
    toggleDensity();
    setOpen(false);
  }

  // Compile full navigable items list
  const items: PaletteItem[] = useMemo(() => {
    const q = query.trim().toLowerCase();
    const resultList: PaletteItem[] = [];

    // 1. Pages / Navigation
    const matchingPages = STATIC_PAGES.filter(
      (p) => !q || p.title.toLowerCase().includes(q) || p.keywords.includes(q) || p.subtitle.toLowerCase().includes(q)
    ).slice(0, q ? 5 : 6);

    matchingPages.forEach((p) => {
      resultList.push({
        id: `page-${p.href}`,
        category: "PAGES",
        title: p.title,
        subtitle: p.subtitle,
        icon: p.icon,
        onSelect: () => navigate(p.href),
      });
    });

    // 2. Quick Actions
    const actions = [
      {
        id: "action-theme",
        title: "Toggle Theme (Dark / Light)",
        subtitle: "Switch color palette mode",
        icon: Sun,
        onSelect: handleThemeClick,
        keywords: "theme dark light mode color",
      },
      {
        id: "action-density",
        title: "Toggle Density (Comfortable / Compact)",
        subtitle: "Switch table row density",
        icon: Rows3,
        onSelect: handleDensityClick,
        keywords: "density compact comfortable spacing rows",
      },
      {
        id: "action-scan",
        title: "Run New Security Scan",
        subtitle: "Launch on-demand target scanner",
        icon: Scan,
        onSelect: () => navigate("/scans"),
        keywords: "scan trigger run analyze new",
      },
      {
        id: "action-reports",
        title: "Export Compliance Report",
        subtitle: "Generate SOC2 or ISO report",
        icon: FileText,
        onSelect: () => navigate("/reports"),
        keywords: "export compliance report download pdf csv",
      },
    ];

    const matchingActions = actions.filter(
      (a) => !q || a.title.toLowerCase().includes(q) || a.keywords.includes(q)
    );

    matchingActions.forEach((a) => {
      resultList.push({
        id: a.id,
        category: "ACTIONS",
        title: a.title,
        subtitle: a.subtitle,
        icon: a.icon,
        onSelect: a.onSelect,
      });
    });

    // 3. Targets (from API)
    if (apiResults && apiResults.targets.length > 0) {
      apiResults.targets.slice(0, 5).forEach((t) => {
        resultList.push({
          id: `target-${t.id}`,
          category: "TARGETS",
          title: t.name,
          subtitle: t.repo_url || undefined,
          icon: GitBranch,
          onSelect: () => navigate(`/targets/${t.id}`),
        });
      });
    }

    // 4. Findings (from API)
    if (apiResults && apiResults.findings.length > 0) {
      apiResults.findings.slice(0, 8).forEach((f) => {
        resultList.push({
          id: `finding-${f.id}`,
          category: "FINDINGS",
          title: f.title,
          subtitle: `${f.tool} · ${f.file_path}`,
          icon: FileCode,
          badge: <SeverityChip severity={f.severity} size="sm" />,
          onSelect: () => navigate(`/findings?search=${encodeURIComponent(f.title)}`),
        });
      });
    }

    return resultList;
  }, [query, apiResults, navigate]);

  // Keyboard navigation handler
  function handleKeyDown(e: React.KeyboardEvent) {
    if (items.length === 0) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex((prev) => (prev + 1) % items.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex((prev) => (prev - 1 + items.length) % items.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const current = items[activeIndex];
      if (current) {
        current.onSelect();
      }
    }
  }

  // Auto-scroll active item
  useEffect(() => {
    const listEl = listRef.current;
    if (!listEl) return;
    const activeEl = listEl.querySelector(`[data-active="true"]`);
    if (activeEl) {
      activeEl.scrollIntoView({ block: "nearest" });
    }
  }, [activeIndex]);

  // Group items by category for rendering
  const groupedCategories = useMemo(() => {
    const map = new Map<string, { item: PaletteItem; globalIdx: number }[]>();
    items.forEach((item, globalIdx) => {
      const list = map.get(item.category) || [];
      list.push({ item, globalIdx });
      map.set(item.category, list);
    });
    return Array.from(map.entries());
  }, [items]);

  return (
    <>
      <button
        onClick={() => {
          // Clearing the previous search belongs in render/trigger: the
          // palette must never paint the last session's query for a frame when it
          // reopens. Results follow from the query, so clearing it is enough. Focus
          // stays in an effect; it touches the DOM, not state.
          setQuery("");
          setActiveIndex(0);
          setOpen(true);
        }}
        title="Search & Commands (Cmd+K)"
        className={cn(
          "flex items-center gap-2 rounded-md border border-sidebar-border bg-sidebar-accent/30 px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent/50 hover:text-foreground",
          collapsed ? "w-auto justify-center px-2" : "w-full justify-between"
        )}
      >
        <span className="flex items-center gap-2">
          <IconWrapper icon={Search} size="sm" />
          {!collapsed && <span>Search or command...</span>}
        </span>
        {!collapsed && (
          <kbd className="flex items-center gap-0.5 rounded border border-sidebar-border bg-sidebar px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
            <span>⌘</span>K
          </kbd>
        )}
      </button>

      {open && isClient && createPortal(
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-start justify-center bg-background/80 backdrop-blur-xs pt-[12vh] px-4 animate-in fade-in"
          onClick={() => setOpen(false)}
        >
          <Card
            className="w-full max-w-2xl border-border bg-card py-0 shadow-2xl overflow-hidden rounded-xl animate-in zoom-in-95 duration-150"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Input Header */}
            <div className="flex items-center gap-3 border-b border-border px-4 py-3.5 bg-card">
              <IconWrapper icon={Command} size="md" tone="primary" />
              <Input
                ref={inputRef}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setActiveIndex(0);
                }}
                onKeyDown={handleKeyDown}
                placeholder="Search findings, targets, pages, or run action..."
                className="h-auto border-0 bg-transparent p-0 text-sm placeholder:text-muted-foreground shadow-none focus-visible:ring-0"
              />
              {query && (
                <button
                  onClick={() => {
                    setQuery("");
                    setActiveIndex(0);
                  }}
                  className="text-xs text-muted-foreground hover:text-foreground mr-1"
                >
                  Clear
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                className="text-muted-foreground hover:text-foreground p-0.5 rounded-md hover:bg-secondary"
              >
                <IconWrapper icon={X} size="md" />
              </button>
            </div>

            {/* Results List */}
            <div
              ref={listRef}
              role="listbox"
              className="max-h-[58vh] overflow-y-auto p-2 space-y-3"
            >
              {loading && (
                <div className="flex items-center justify-center py-6 text-xs text-muted-foreground">
                  <span className="animate-pulse">Searching repository and vulnerability index...</span>
                </div>
              )}

              {!loading && items.length === 0 && (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  No matches found for &quot;{query}&quot;.
                </div>
              )}

              {groupedCategories.map(([category, entries]) => (
                <div key={category} className="space-y-1">
                  <div className="px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {category}
                  </div>
                  {entries.map(({ item, globalIdx }) => {
                    const isSelected = globalIdx === activeIndex;
                    return (
                      <div
                        key={item.id}
                        role="option"
                        aria-selected={isSelected}
                        data-active={isSelected}
                        onClick={item.onSelect}
                        onMouseEnter={() => setActiveIndex(globalIdx)}
                        className={cn(
                          "flex cursor-pointer items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition-colors",
                          isSelected
                            ? "bg-accent text-accent-foreground font-medium"
                            : "text-foreground hover:bg-secondary/60"
                        )}
                      >
                        <div className="flex min-w-0 items-center gap-3">
                          <div
                            className={cn(
                              "flex h-7 w-7 shrink-0 items-center justify-center rounded-md border",
                              isSelected
                                ? "border-primary/40 bg-primary/10 text-primary"
                                : "border-border bg-secondary text-muted-foreground"
                            )}
                          >
                            <IconWrapper icon={item.icon} size="sm" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-xs font-semibold">{item.title}</div>
                            {item.subtitle && (
                              <div className="truncate text-[11px] text-muted-foreground font-normal">
                                {item.subtitle}
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="flex shrink-0 items-center gap-2">
                          {item.badge}
                          {isSelected && <ArrowRight className="h-3.5 w-3.5 text-primary" />}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>

            {/* Keyboard Helper Footer */}
            <div className="flex items-center justify-between border-t border-border bg-secondary/30 px-4 py-2 text-[11px] text-muted-foreground">
              <div className="flex items-center gap-3">
                <span>
                  <kbd className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[10px]">↑</kbd>{" "}
                  <kbd className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[10px]">↓</kbd> Navigate
                </span>
                <span>
                  <kbd className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[10px]">↵</kbd> Select
                </span>
                <span>
                  <kbd className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[10px]">esc</kbd> Dismiss
                </span>
              </div>
              <span className="font-mono text-[10px]">Toleman Cmd+K</span>
            </div>
          </Card>
        </div>,
        document.body
      )}
    </>
  );
}
