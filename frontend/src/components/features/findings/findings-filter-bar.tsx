"use client";

import { useState, useEffect } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Group, Target } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Icon } from "@/components/ui/icon";
import { GroupFilter } from "@/components/group-filter";
import { Search, X, Filter, ShieldAlert, Wrench, CircleDot, Bookmark, Plus } from "lucide-react";

const STATES = ["Open", "Accepted Risk", "False Positive", "Won't Fix", "Mitigated", "Reopened"];

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

/**
 * Multi-criteria filter bar for the Findings list.
 *
 * Synchronizes filter criteria (severity, fixability, tool, state, target, group, search)
 * with URL search params to ensure shareable, bookmarkable triage states.
 * Provides one-click quick triage preset views and active filter removal pills.
 */
export function FindingsFilterBar({
  targets,
  tools,
  groups,
}: {
  targets: Target[];
  tools: string[];
  groups: Group[];
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [search, setSearch] = useState(searchParams.get("search") ?? "");

  const activeSeverity = searchParams.get("severity") ?? "";
  const activeFixability = searchParams.get("fixability") ?? "";
  const activeTool = searchParams.get("tool") ?? "";
  const activeState = searchParams.get("state") ?? "";
  const activeTargetId = searchParams.get("target_id") ?? "";
  const activeGroupId = searchParams.get("group_id") ?? "";
  const activeSearch = searchParams.get("search") ?? "";

  function updateParams(newEntries: Record<string, string | null>) {
    const params = new URLSearchParams(searchParams.toString());
    Object.entries(newEntries).forEach(([key, value]) => {
      if (value) {
        params.set(key, value);
      } else {
        params.delete(key);
      }
    });
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    updateParams({ search: search.trim() ? search.trim() : null });
  }

  function clearAll() {
    setSearch("");
    router.push(pathname);
  }

  // Active filter pills calculation
  const activePills: { id: string; label: string; value: string; onRemove: () => void }[] = [];

  if (activeSearch) {
    activePills.push({
      id: "search",
      label: "Search",
      value: activeSearch,
      onRemove: () => {
        setSearch("");
        updateParams({ search: null });
      },
    });
  }
  if (activeSeverity) {
    activePills.push({
      id: "severity",
      label: "Severity",
      value: activeSeverity,
      onRemove: () => updateParams({ severity: null }),
    });
  }
  if (activeFixability) {
    const labelMap: Record<string, string> = {
      fixable: "Fix available",
      no_known_fix: "No known fix",
      unknown: "Fixability unknown",
    };
    activePills.push({
      id: "fixability",
      label: "Fixability",
      value: labelMap[activeFixability] || activeFixability,
      onRemove: () => updateParams({ fixability: null }),
    });
  }
  if (activeTool) {
    activePills.push({
      id: "tool",
      label: "Tool",
      value: activeTool,
      onRemove: () => updateParams({ tool: null }),
    });
  }
  if (activeState) {
    activePills.push({
      id: "state",
      label: "State",
      value: activeState,
      onRemove: () => updateParams({ state: null }),
    });
  }
  if (activeTargetId) {
    const targetName = targets.find((t) => String(t.id) === activeTargetId)?.name || activeTargetId;
    activePills.push({
      id: "target",
      label: "Target",
      value: targetName,
      onRemove: () => updateParams({ target_id: null }),
    });
  }
  if (activeGroupId) {
    const groupName = groups.find((g) => String(g.id) === activeGroupId)?.name || activeGroupId;
    activePills.push({
      id: "group",
      label: "Group",
      value: groupName,
      onRemove: () => updateParams({ group_id: null }),
    });
  }

  // Preset Views check
  const isAllPreset = activePills.length === 0;
  const isCriticalPreset = activeSeverity === "Critical" && !activeFixability && !activeTool && !activeState && !activeTargetId && !activeGroupId && !activeSearch;
  const isFixablePreset = activeFixability === "fixable" && !activeSeverity && !activeTool && !activeState && !activeTargetId && !activeGroupId && !activeSearch;
  const isOpenPreset = activeState === "Open" && !activeSeverity && !activeFixability && !activeTool && !activeTargetId && !activeGroupId && !activeSearch;

  // Custom Saved Views (P4)
  const [savedViews, setSavedViews] = useState<{ id: string; name: string; params: Record<string, string> }[]>([]);
  const [isSavingView, setIsSavingView] = useState(false);
  const [newViewName, setNewViewName] = useState("");

  /**
   * Synchronize custom saved views from localStorage upon client mount.
   * Defers state update via `queueMicrotask` to prevent synchronous cascading renders
   * flagged by React 19's `react-hooks/set-state-in-effect` rule.
   */
  useEffect(() => {
    try {
      const raw = localStorage.getItem("toleman_saved_filter_views");
      if (raw) {
        const parsed = JSON.parse(raw);
        queueMicrotask(() => {
          setSavedViews(parsed);
        });
      }
    } catch {
      // Ignore localStorage read errors in restricted/SSR contexts
    }
  }, []);

  function persistSavedViews(views: { id: string; name: string; params: Record<string, string> }[]) {
    setSavedViews(views);
    try {
      localStorage.setItem("toleman_saved_filter_views", JSON.stringify(views));
    } catch {
      // Ignore localStorage write errors
    }
  }

  function handleSaveCurrentView(e: React.FormEvent) {
    e.preventDefault();
    if (!newViewName.trim()) return;
    const currentParams: Record<string, string> = {};
    searchParams.forEach((val, key) => {
      if (key !== "page") currentParams[key] = val;
    });

    const newView = {
      id: `view_${Date.now()}`,
      name: newViewName.trim(),
      params: currentParams,
    };

    persistSavedViews([...savedViews, newView]);
    setNewViewName("");
    setIsSavingView(false);
  }

  function handleDeleteSavedView(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    persistSavedViews(savedViews.filter((v) => v.id !== id));
  }

  function applySavedView(paramsMap: Record<string, string>) {
    const params = new URLSearchParams(paramsMap);
    router.push(`${pathname}?${params.toString()}`);
  }

  function isSavedViewActive(paramsMap: Record<string, string>) {
    const currentKeys = Array.from(searchParams.keys()).filter((k) => k !== "page");
    const viewKeys = Object.keys(paramsMap);
    if (currentKeys.length !== viewKeys.length) return false;
    return viewKeys.every((k) => searchParams.get(k) === paramsMap[k]);
  }

  return (
    <div className="space-y-3">
      {/* Quick Triage Presets & Custom Saved Views */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border/60 pb-2.5">
        <span className="mr-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Views:
        </span>
        <button
          type="button"
          onClick={clearAll}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
            isAllPreset
              ? "bg-primary text-primary-foreground shadow-xs"
              : "bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground"
          }`}
        >
          <Icon icon={Filter} size="xs" />
          All Findings
        </button>
        <button
          type="button"
          onClick={() => updateParams({ severity: "Critical", fixability: null, tool: null, state: null, target_id: null, group_id: null, search: null })}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
            isCriticalPreset
              ? "bg-destructive text-destructive-foreground shadow-xs"
              : "bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground"
          }`}
        >
          <Icon icon={ShieldAlert} size="xs" />
          Critical Only
        </button>
        <button
          type="button"
          onClick={() => updateParams({ fixability: "fixable", severity: null, tool: null, state: null, target_id: null, group_id: null, search: null })}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
            isFixablePreset
              ? "bg-chart-5 text-success-foreground shadow-xs"
              : "bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground"
          }`}
        >
          <Icon icon={Wrench} size="xs" />
          Fix Available
        </button>
        <button
          type="button"
          onClick={() => updateParams({ state: "Open", severity: null, fixability: null, tool: null, target_id: null, group_id: null, search: null })}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
            isOpenPreset
              ? "bg-chart-3 text-warning-foreground shadow-xs"
              : "bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground"
          }`}
        >
          <Icon icon={CircleDot} size="xs" />
          Open Active
        </button>

        {/* Custom Saved Views List */}
        {savedViews.map((sv) => {
          const active = isSavedViewActive(sv.params);
          return (
            <button
              key={sv.id}
              type="button"
              onClick={() => applySavedView(sv.params)}
              className={`group inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                active
                  ? "bg-accent-strong text-white shadow-xs"
                  : "bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground"
              }`}
            >
              <Bookmark className="h-3 w-3 shrink-0" />
              <span>{sv.name}</span>
              <span
                role="button"
                tabIndex={0}
                onClick={(e) => handleDeleteSavedView(sv.id, e)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    handleDeleteSavedView(sv.id, e as unknown as React.MouseEvent);
                  }
                }}
                className="ml-0.5 opacity-60 hover:opacity-100 hover:text-destructive"
                aria-label={`Delete saved view ${sv.name}`}
              >
                <X className="h-3 w-3" />
              </span>
            </button>
          );
        })}

        {/* Save Current View Action */}
        {!isSavingView && activePills.length > 0 && (
          <button
            type="button"
            onClick={() => setIsSavingView(true)}
            className="inline-flex items-center gap-1 rounded-full border border-dashed border-border px-2.5 py-1 text-xs font-medium text-muted-foreground hover:border-primary hover:text-foreground"
          >
            <Plus className="h-3 w-3" />
            Save View
          </button>
        )}

        {/* Save View Inline Input */}
        {isSavingView && (
          <form onSubmit={handleSaveCurrentView} className="inline-flex items-center gap-1.5">
            <Input
              autoFocus
              className="h-6 w-36 bg-secondary px-2 text-xs"
              placeholder="View name..."
              value={newViewName}
              onChange={(e) => setNewViewName(e.target.value)}
            />
            <Button size="sm" type="submit" className="h-6 px-2 text-xs">
              Save
            </Button>
            <Button
              size="sm"
              variant="ghost"
              type="button"
              onClick={() => {
                setIsSavingView(false);
                setNewViewName("");
              }}
              className="h-6 px-1.5 text-xs text-muted-foreground"
            >
              Cancel
            </Button>
          </form>
        )}
      </div>

      {/* Main Filter Controls Container */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card p-3 shadow-xs">
        <form onSubmit={submitSearch} className="flex min-w-[220px] flex-1 items-center gap-2">
          <div className="relative flex-1">
            <Icon icon={Search} size="sm" tone="muted" className="absolute left-2.5 top-1/2 -translate-y-1/2" />
            <Input
              className="h-8 pl-8 text-xs bg-secondary"
              placeholder="Search title, file path, rule id..."
              aria-label="Search findings"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {search && (
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  updateParams({ search: null });
                }}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label="Clear search input"
              >
                <Icon icon={X} size="xs" />
              </button>
            )}
          </div>
          <Button type="submit" size="sm" variant="outline" className="h-8 text-xs shrink-0">
            Search
          </Button>
        </form>

        <select
          aria-label="Filter by severity"
          className={SELECT_CLASS}
          value={activeSeverity}
          onChange={(e) => updateParams({ severity: e.target.value || null })}
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        {/* (#246) "Which of these can I close today?", the question severity
            cannot answer. "Unknown" is offered as its own choice rather than
            folded into "No known fix": for most SAST and secrets findings we
            have no advisory to look up, and claiming there is no fix for a
            hardcoded secret would be plainly wrong. */}
        <select
          aria-label="Filter by fixability"
          className={SELECT_CLASS}
          value={activeFixability}
          onChange={(e) => updateParams({ fixability: e.target.value || null })}
        >
          <option value="">Any fixability</option>
          <option value="fixable">Fix available</option>
          <option value="no_known_fix">No known fix</option>
          <option value="unknown">Fixability unknown</option>
        </select>

        <select
          aria-label="Filter by tool"
          className={SELECT_CLASS}
          value={activeTool}
          onChange={(e) => updateParams({ tool: e.target.value || null })}
        >
          <option value="">All tools</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by state"
          className={SELECT_CLASS}
          value={activeState}
          onChange={(e) => updateParams({ state: e.target.value || null })}
        >
          <option value="">All states</option>
          {STATES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by target"
          className={SELECT_CLASS}
          value={activeTargetId}
          onChange={(e) => updateParams({ target_id: e.target.value || null })}
        >
          <option value="">All targets</option>
          {targets.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>

        {groups.length > 0 && <GroupFilter groups={groups} />}
      </div>

      {/* Active Filter Pills List */}
      {activePills.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          <span className="text-[11px] font-medium text-muted-foreground mr-1">Active filters:</span>
          {activePills.map((pill) => (
            <span
              key={pill.id}
              className="inline-flex items-center gap-1 rounded-full border border-border bg-secondary px-2.5 py-0.5 text-xs text-foreground"
            >
              <span className="text-muted-foreground">{pill.label}:</span>
              <span className="font-semibold">{pill.value}</span>
              <button
                type="button"
                onClick={pill.onRemove}
                className="ml-0.5 text-muted-foreground hover:text-destructive"
                aria-label={`Remove filter ${pill.label} ${pill.value}`}
              >
                <Icon icon={X} size="xs" />
              </button>
            </span>
          ))}
          <button
            type="button"
            onClick={clearAll}
            className="text-xs text-muted-foreground underline hover:text-foreground ml-1"
          >
            Clear all
          </button>
        </div>
      )}
    </div>
  );
}
