"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Search, ShieldAlert, GitBranch, X } from "lucide-react";
import { api, SearchResults } from "@/lib/api";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_COLOR } from "@/lib/severity";
import { cn } from "@/lib/utils";

/** Sidebar search trigger + Cmd/Ctrl+K command-palette-style overlay searching
 * findings (title/file_path/rule_id/cve_id) and targets (name/repo_url) via
 * GET /api/search. */
export function GlobalSearch({ collapsed }: { collapsed?: boolean }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (open) {
      // Wait a tick for the overlay to mount before focusing.
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
    setQuery("");
    setResults(null);
  }, [open]);

  useEffect(() => {
    const q = query.trim();
    if (!q) {
      setResults(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    const handle = setTimeout(() => {
      api
        .search(q)
        .then(setResults)
        .catch(() => setResults({ findings: [], targets: [] }))
        .finally(() => setLoading(false));
    }, 200);
    return () => clearTimeout(handle);
  }, [query]);

  function go(href: string) {
    setOpen(false);
    router.push(href);
  }

  const hasResults = results && (results.findings.length > 0 || results.targets.length > 0);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title="Search (Cmd+K)"
        className={cn(
          "flex items-center gap-2 rounded-md border border-sidebar-border bg-sidebar-accent/30 px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent/50 hover:text-foreground",
          collapsed ? "w-auto justify-center px-2" : "w-full justify-between"
        )}
      >
        <span className="flex items-center gap-2">
          <Search className="h-3.5 w-3.5 shrink-0" />
          {!collapsed && <span>Search...</span>}
        </span>
        {!collapsed && (
          <kbd className="rounded border border-sidebar-border bg-sidebar px-1.5 py-0.5 text-[10px] text-muted-foreground">
            ⌘K
          </kbd>
        )}
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[15vh]" onClick={() => setOpen(false)}>
          <Card
            className="w-full max-w-lg border-border bg-card py-0 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-border px-4 py-3">
              <Search className="h-4 w-4 shrink-0 text-muted-foreground" />
              <Input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search findings and targets..."
                className="h-auto border-0 bg-transparent p-0 shadow-none focus-visible:ring-0"
              />
              <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="max-h-[50vh] overflow-y-auto px-2 py-2">
              {!query.trim() && (
                <p className="px-2 py-3 text-sm text-muted-foreground">
                  Type to search across findings and targets.
                </p>
              )}

              {query.trim() && loading && !results && (
                <p className="px-2 py-3 text-sm text-muted-foreground">Searching...</p>
              )}

              {query.trim() && results && !hasResults && !loading && (
                <p className="px-2 py-3 text-sm text-muted-foreground">No results for &quot;{query}&quot;.</p>
              )}

              {results && results.targets.length > 0 && (
                <div className="mb-2">
                  <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Targets
                  </div>
                  {results.targets.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => go(`/targets/${t.id}`)}
                      className="flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-sm hover:bg-accent"
                    >
                      <GitBranch className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <div className="flex min-w-0 flex-col">
                        <span className="truncate text-foreground">{t.name}</span>
                        <span className="truncate text-xs text-muted-foreground">{t.repo_url}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {results && results.findings.length > 0 && (
                <div>
                  <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Findings
                  </div>
                  {results.findings.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => go(`/targets/${f.target_id}`)}
                      className="flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-sm hover:bg-accent"
                    >
                      <ShieldAlert className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <div className="flex min-w-0 flex-1 flex-col">
                        <span className="truncate text-foreground">{f.title}</span>
                        <span className="truncate text-xs text-muted-foreground">{f.file_path}</span>
                      </div>
                      <Badge variant="outline" className={cn("shrink-0", SEVERITY_COLOR[f.severity])}>
                        {f.severity}
                      </Badge>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
