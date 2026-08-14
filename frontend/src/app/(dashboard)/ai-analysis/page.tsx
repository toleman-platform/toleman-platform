"use client";

import { useEffect, useRef, useState } from "react";
import { Search, X } from "lucide-react";
import { api, AiRecentAnalysis, Finding } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SEVERITY_COLOR } from "@/lib/severity";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, timeAgo } from "@/lib/utils";

// Issue #122: the page previously said "select a finding" with no control
// anywhere on the page to do so -- a dead end when landed on directly
// rather than deep-linked from Findings. This adds a real entry point: a
// typeahead finding search (by title/CVE/target, reusing GET
// /api/findings?search=...) and a "recent analyses" list backed by
// GET /api/ai/recent so returning users land on something useful instead
// of two empty states.
export default function AiAnalysisPage() {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [provider, setProvider] = useState<"anthropic" | "openai_compatible">("anthropic");

  const [query, setQuery] = useState("");
  // Tagged with the query it was fetched for, so a still-in-flight fetch
  // from a since-changed query can't flash stale results, and "searching"
  // can be derived instead of tracked as its own state (avoids setting
  // state synchronously in the debounce effect body below).
  const [searchResults, setSearchResults] = useState<{ query: string; items: Finding[] } | null>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const searchBoxRef = useRef<HTMLDivElement>(null);

  const [selected, setSelected] = useState<Finding | null>(null);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [recent, setRecent] = useState<AiRecentAnalysis[] | null>(null);

  function loadRecent() {
    api
      .aiRecentAnalyses()
      .then(setRecent)
      .catch(() => setRecent([]));
  }

  useEffect(() => {
    api.aiStatus().then((s) => {
      setConfigured(s.configured);
      setProvider(s.provider);
    });
    loadRecent();
  }, []);

  // Typeahead: debounced search over open findings by title/CVE/target,
  // reusing GET /api/findings?search=... rather than new backend search
  // logic (see backend/app/api/findings.py's list_findings). setState only
  // happens inside the async .then/.catch callbacks below, not
  // synchronously in the effect body.
  useEffect(() => {
    const q = query.trim();
    if (!q) return;
    const handle = setTimeout(() => {
      api
        .findings({ search: q, state: "Open", page_size: 8 })
        .then((r) => setSearchResults({ query: q, items: r.items }))
        .catch(() => setSearchResults({ query: q, items: [] }));
    }, 250);
    return () => clearTimeout(handle);
  }, [query]);

  const trimmedQuery = query.trim();
  const resultsForQuery = searchResults?.query === trimmedQuery ? searchResults.items : null;
  const searching = trimmedQuery.length > 0 && resultsForQuery === null;

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (searchBoxRef.current && !searchBoxRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  function pickFinding(finding: Finding) {
    setSelected(finding);
    setAnalysis(null);
    setError(null);
    setQuery("");
    setSearchResults(null);
    setDropdownOpen(false);
  }

  function clearSelection() {
    setSelected(null);
    setAnalysis(null);
    setError(null);
  }

  async function analyze(findingId: number) {
    setLoading(true);
    setError(null);
    setAnalysis(null);
    try {
      const res = await api.analyzeFinding(findingId);
      setAnalysis(res.analysis);
      loadRecent(); // this finding is now (or freshly) in the recent-analyses list
    } catch (e) {
      setError(e instanceof Error ? e.message : "analysis failed");
    } finally {
      setLoading(false);
    }
  }

  async function viewRecent(item: AiRecentAnalysis) {
    setSelected({
      id: item.finding_id,
      target_id: item.target_id,
      tool: "",
      rule_id: "",
      title: item.title,
      description: "",
      file_path: "",
      line_start: null,
      line_end: null,
      severity: item.severity,
      priority_score: 0,
      branch: "",
      state: item.state,
      cve_id: item.cve_id,
      epss_score: null,
      kev_listed: false,
      first_seen: "",
      last_seen: "",
      sla_days: null,
      sla_violated: false,
    });
    setAnalysis(null);
    setError(null);
    await analyze(item.finding_id);
  }

  const providerLabel = provider === "openai_compatible" ? "your configured model" : "Claude";

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">AI Analysis</h1>
        <p className="text-sm text-muted-foreground">{providerLabel}-generated remediation guidance for a selected finding</p>
      </div>

      {configured === null && (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-9 w-full max-w-md" />
          <Skeleton className="h-9 w-32" />
        </div>
      )}

      {configured === false && (
        <Card className="border-border bg-card">
          <CardContent className="px-4 py-3 text-sm text-muted-foreground">
            Not configured. Set an AI provider in <code className="text-foreground">Admin &gt; Global Integrations</code>{" "}
            (Anthropic API key, or a self-hosted/OpenAI-compatible endpoint like Ollama or Kimi) to enable this
            feature. Search and the recent-analyses list below still work once a finding is selected — analysis
            itself returns a clear &quot;not configured&quot; message rather than erroring.
          </CardContent>
        </Card>
      )}

      {configured !== null && (
        <>
          {/* Finding search: the real entry point (issue #122) */}
          <div ref={searchBoxRef} className="relative flex flex-col gap-1.5 max-w-xl">
            <label className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Finding</label>

            {selected ? (
              <div className="flex items-center gap-2 rounded-md border border-input bg-secondary px-3 py-2 text-sm">
                <Badge variant="outline" className={cn("shrink-0", SEVERITY_COLOR[selected.severity])}>
                  {selected.severity}
                </Badge>
                <span className="min-w-0 flex-1 truncate text-foreground">{selected.title}</span>
                <button
                  onClick={clearSelection}
                  className="shrink-0 text-muted-foreground hover:text-foreground"
                  aria-label="Clear selected finding"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            ) : (
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onFocus={() => setDropdownOpen(true)}
                  placeholder="Search open findings by title, CVE, or target..."
                  className="pl-9"
                  aria-label="Search open findings by title, CVE, or target"
                />
              </div>
            )}

            {!selected && dropdownOpen && query.trim() && (
              <Card className="absolute top-full z-20 mt-1 w-full border-border bg-card py-0 shadow-lg">
                <div className="max-h-80 overflow-y-auto py-1">
                  {searching && (
                    <p className="px-3 py-2 text-sm text-muted-foreground">Searching...</p>
                  )}
                  {resultsForQuery && resultsForQuery.length === 0 && (
                    <p className="px-3 py-2 text-sm text-muted-foreground">No open findings match &quot;{query}&quot;.</p>
                  )}
                  {resultsForQuery?.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => pickFinding(f)}
                      className="flex w-full items-center gap-3 px-3 py-2 text-left text-sm hover:bg-accent"
                    >
                      <Badge variant="outline" className={cn("shrink-0", SEVERITY_COLOR[f.severity])}>
                        {f.severity}
                      </Badge>
                      <span className="min-w-0 flex-1 truncate text-foreground">{f.title}</span>
                      <span className="shrink-0 font-mono text-xs text-muted-foreground">
                        {f.cve_id ? `${f.cve_id} · ` : ""}
                        {f.file_path}
                      </span>
                    </button>
                  ))}
                </div>
              </Card>
            )}
          </div>

          {selected && (
            <Button onClick={() => analyze(selected.id)} disabled={loading} className="self-start">
              {loading ? "Analyzing..." : `Analyze with ${providerLabel}`}
            </Button>
          )}

          {error && <p className="text-sm text-destructive">{error}</p>}

          {analysis && selected && (
            <Card className="border-border bg-card">
              <CardContent className="px-4 py-4">
                <Badge variant="outline" className={SEVERITY_COLOR[selected.severity]}>
                  {selected.severity}
                </Badge>
                <p className="mt-3 whitespace-pre-wrap text-sm text-foreground">{analysis}</p>
              </CardContent>
            </Card>
          )}

          {/* Recent analyses: real landing state instead of an empty page
              on first load (issue #122). */}
          <Card className="border-border bg-card max-w-3xl">
            <CardContent className="px-4 py-4">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-foreground">Recent analyses</h3>
                {recent && recent.length > 0 && (
                  <span className="font-mono text-xs text-muted-foreground">{recent.length} recent</span>
                )}
              </div>

              {recent === null && (
                <div className="flex flex-col gap-2">
                  <Skeleton className="h-9 w-full" />
                  <Skeleton className="h-9 w-full" />
                </div>
              )}

              {recent && recent.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  No findings analyzed yet. Search above to run your first AI analysis.
                </p>
              )}

              {recent && recent.length > 0 && (
                <div className="flex flex-col">
                  {recent.map((item) => (
                    <div
                      key={item.finding_id}
                      className="flex items-center gap-3 border-b border-border py-2.5 last:border-b-0"
                    >
                      <Badge variant="outline" className={cn("shrink-0", SEVERITY_COLOR[item.severity])}>
                        {item.severity}
                      </Badge>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium text-foreground">{item.title}</div>
                        <div className="truncate font-mono text-xs text-muted-foreground">
                          {item.cve_id ? `${item.cve_id} · ` : ""}
                          {item.target_name}
                        </div>
                      </div>
                      <span className="shrink-0 text-xs text-muted-foreground">{timeAgo(item.last_analyzed_at)}</span>
                      <button
                        onClick={() => viewRecent(item)}
                        className="shrink-0 font-mono text-xs text-accent-strong hover:underline"
                      >
                        View &rarr;
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
