"use client";

import { useState } from "react";
import { ChevronRight, Loader2 } from "lucide-react";
import { Finding, FindingGroup, FindingsQuery, Target, api } from "@/lib/api";
import {
  EPSS_BADGE_COLOR,
  EPSS_NOTABLE_THRESHOLD,
  KEV_BADGE_COLOR,
  SEVERITY_BORDER_COLOR,
  SEVERITY_COLOR,
} from "@/lib/severity";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { parseServerTimestamp } from "@/lib/format/date";

const TRIAGE_STATES = ["Accepted Risk", "False Positive", "Won't Fix"];

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Whole days between `iso` and `now`, floored at 0.
 *
 * `now` is passed in rather than read here so a row's age cannot change
 * between two renders of the same data — the same reason SlaBadge in
 * finding-row.tsx captures the clock once at mount.
 */
export function daysSince(iso: string, now: number): number {
  const then = parseServerTimestamp(iso);
  if (Number.isNaN(then)) return 0;
  return Math.max(0, Math.floor((now - then) / MS_PER_DAY));
}

/** "2d", "64d", "1y 2d" — short enough for a column, exact enough to act on. */
export function formatAge(days: number): string {
  if (days < 365) return `${days}d`;
  const years = Math.floor(days / 365);
  return `${years}y ${days - years * 365}d`;
}

/**
 * The subject of a group row, with the part that varies between rows first.
 *
 * A licence group's rule id is `license:LGPL-3.0-or-later`; the prefix is
 * identical on every licence row, so it is dropped and the licence itself
 * leads. Everything else shows its rule id, which is already the thing that
 * differs — a CVE, a Checkov check, a Semgrep rule.
 */
export function groupSubject(group: FindingGroup): string {
  if (group.rule_id.startsWith("license:")) return group.rule_id.slice("license:".length);
  return group.rule_id;
}

function GroupSignals({ group }: { group: FindingGroup }) {
  const signals: React.ReactNode[] = [];

  if (group.kev_count > 0) {
    signals.push(
      <Badge
        key="kev"
        variant="outline"
        title="Listed in CISA's Known Exploited Vulnerabilities catalogue"
        className={cn("px-1.5 py-0 text-[10px] font-semibold", KEV_BADGE_COLOR)}
      >
        KEV {group.kev_count > 1 ? `×${group.kev_count}` : ""}
      </Badge>,
    );
  }

  if (group.max_epss !== null && group.max_epss > EPSS_NOTABLE_THRESHOLD) {
    signals.push(
      <Badge
        key="epss"
        variant="outline"
        title="Highest EPSS score in this group: predicted probability of exploitation in the next 30 days"
        className={cn("px-1.5 py-0 text-[10px]", EPSS_BADGE_COLOR)}
      >
        EPSS {Math.round(group.max_epss * 100)}%
      </Badge>,
    );
  }

  if (group.fixability === "fixable") {
    signals.push(
      <Badge
        key="fix"
        variant="outline"
        title="An upgrade that resolves this is available"
        className="border-success/30 bg-success/10 px-1.5 py-0 text-[10px] text-success"
      >
        Fix available
      </Badge>,
    );
  }

  if (group.sla_violated) {
    signals.push(
      <Badge
        key="sla"
        variant="outline"
        title="Open past its SLA window"
        className="border-destructive/30 bg-destructive/10 px-1.5 py-0 text-[10px] text-destructive"
      >
        Overdue
      </Badge>,
    );
  }

  if (signals.length === 0) return null;
  return <div className="flex flex-wrap items-center gap-1">{signals}</div>;
}

/**
 * Members are fetched a page at a time; this bounds how many a single row will
 * pull before it stops and says so. A licence group with 148 members is the
 * case this exists for — it must be triageable in one action — but an
 * unbounded loop on a pathological group is not something a row should do.
 */
const MEMBER_PAGE_SIZE = 200;
const MEMBER_FETCH_CAP = 1000;

/**
 * One decision, as one line.
 *
 * The old card spent four lines and a border on six facts about a single
 * detection. This spends one line on the same six facts about a whole group,
 * and the member findings stay one click away rather than being pre-expanded
 * into the page — which is the entire difference between 150 rows and 14.
 */
export function FindingGroupRow({
  group,
  memberQuery,
  targets = [],
  onTriaged,
}: {
  group: FindingGroup;
  /**
   * The exact filters the grouped list was built with.
   *
   * Without this the member fetch sent only `tool` and `rule_id`, so expanding
   * a row in the "Needs action" queue listed findings the queue excludes --
   * and because group triage acts on what the fetch returned, one click could
   * overwrite findings triaged months ago, complete with a new rationale and a
   * new state-log entry, none of which the reader was shown. The row's count
   * comes from the filtered aggregate, so its member list has to come from the
   * same filters or the two disagree.
   */
  memberQuery?: FindingsQuery;
  targets?: Target[];
  onTriaged?: () => void;
}) {
  const [now] = useState(() => Date.now());
  const [expanded, setExpanded] = useState(false);
  const [members, setMembers] = useState<Finding[] | null>(null);
  const [memberTotal, setMemberTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const targetName = targets.find((t) => t.id === group.representative_target_id)?.name;
  const age = daysSince(group.oldest_first_seen, now);

  // More members than one row will pull. Triage is disabled rather than
  // silently applied to the first slice: a group that renders 1,400 and closes
  // 1,000 would leave 400 behind a decision the reader believes is finished.
  const truncated = members !== null && memberTotal > members.length;

  async function loadMembers() {
    setLoading(true);
    setError(null);
    try {
      const collected: Finding[] = [];
      let page = 1;
      let total = 0;
      // Paged rather than capped at a single request: a group renders its full
      // finding_count, so triaging it has to reach every one of them or the
      // row promises more than the action delivers.
      for (;;) {
        const result = await api.findings({
          ...memberQuery,
          tool: group.tool,
          rule_id: group.rule_id,
          page,
          page_size: MEMBER_PAGE_SIZE,
        });
        total = result.total;
        collected.push(...result.items);
        if (result.items.length === 0 || collected.length >= total || collected.length >= MEMBER_FETCH_CAP) break;
        page += 1;
      }
      setMembers(collected);
      setMemberTotal(total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not load this group's findings");
    } finally {
      setLoading(false);
    }
  }

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    // Members are fetched on first expand and then kept: re-collapsing and
    // re-expanding a row is a navigation gesture, not a reason to re-hit the
    // API. `grouped` rows are the only ones with anything to reveal.
    if (!next || members !== null || !group.grouped) return;
    await loadMembers();
  }

  async function triageGroup(toState: string) {
    // One rationale recorded against every member, which is both fewer clicks
    // and a better audit trail than the same sentence retyped a dozen times.
    const ids = members?.map((m) => m.id) ?? [];
    if (ids.length === 0 || truncated) return;
    setSubmitting(true);
    try {
      await api.bulkTriage(ids, toState, reason);
      setReason("");
      // The members just triaged may no longer match the active filters, and
      // the cached list would otherwise keep showing them with their old
      // states -- a second click would then re-triage findings already in that
      // state. Dropped so the next expand re-reads the truth.
      setMembers(null);
      setMemberTotal(0);
      setExpanded(false);
      onTriaged?.();
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className={cn("border-l-4 border-b border-border bg-card", SEVERITY_BORDER_COLOR[group.severity])}>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={expanded}
        className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-secondary/50"
      >
        <ChevronRight
          aria-hidden="true"
          className={cn(
            "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
            expanded && "rotate-90 text-foreground",
            !group.grouped && "invisible",
          )}
        />

        <Badge
          variant="outline"
          className={cn("shrink-0 px-1.5 py-0 text-[10px] font-bold uppercase tracking-wide", SEVERITY_COLOR[group.severity])}
        >
          {group.severity}
        </Badge>

        <span className="flex min-w-0 flex-1 flex-col">
          <span className="truncate font-mono text-[13px] font-medium text-foreground">
            {groupSubject(group)}
            <span className="ml-2 font-sans font-normal text-muted-foreground">{group.tool}</span>
          </span>
          <span className="truncate text-[11px] text-muted-foreground">
            {targetName ? `${targetName} · ` : ""}
            {group.file_count > 1 ? `${group.file_count} files` : group.representative_file_path}
            {group.target_count > 1 ? ` · ${group.target_count} targets` : ""}
          </span>
        </span>

        <span className="shrink-0 text-right font-mono text-[13px] font-semibold tabular-nums text-foreground">
          {group.finding_count}
          {group.grouped && group.finding_count > 1 && (
            <span className="ml-1 text-[10px] font-normal text-muted-foreground">rows</span>
          )}
        </span>

        <span className="hidden shrink-0 md:block">
          <GroupSignals group={group} />
        </span>

        <span className="hidden w-12 shrink-0 text-right font-mono text-[11px] tabular-nums text-muted-foreground lg:block">
          {formatAge(age)}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-border bg-secondary/30 px-3 py-2 pl-10">
          {!group.grouped && (
            <p className="text-xs text-muted-foreground">
              Not grouped: one {group.category.toLowerCase()} finding is one incident with its own clock, so it
              is never collapsed with others under the same rule.
            </p>
          )}

          {loading && (
            <p className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> Loading this group&apos;s findings…
            </p>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}

          {members && members.length > 0 && (
            <>
              <ul className="flex flex-col">
                {members.map((m) => (
                  <li
                    key={m.id}
                    className="flex items-center gap-3 border-b border-border/60 py-1 font-mono text-[11px] text-muted-foreground last:border-b-0"
                  >
                    <span className="min-w-0 flex-1 truncate text-foreground">{m.title}</span>
                    <span className="shrink-0">#{m.id}</span>
                    <span className="hidden shrink-0 sm:block">{m.file_path}</span>
                  </li>
                ))}
              </ul>

              {truncated && (
                <p className="mt-2 text-xs text-destructive">
                  Showing {members.length} of {memberTotal}. Group triage is disabled above this size — narrow the
                  filters, or triage from the ungrouped list.
                </p>
              )}

              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Input
                  className="h-7 min-w-[180px] flex-1 bg-background text-xs"
                  aria-label={`Rationale, applied to all ${members.length} findings in this group`}
                  disabled={submitting || truncated}
                  placeholder="Rationale (recorded against every finding in this group)"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
                {TRIAGE_STATES.map((s) => (
                  <Button
                    key={s}
                    size="sm"
                    variant={s === "Won't Fix" ? "destructive" : "outline"}
                    className="h-7 text-xs"
                    disabled={submitting || truncated}
                    onClick={() => triageGroup(s)}
                  >
                    {submitting ? "Updating…" : s}
                  </Button>
                ))}
              </div>
            </>
          )}

          {members && members.length === 0 && (
            <p className="text-xs text-muted-foreground">No findings matched this group.</p>
          )}
        </div>
      )}
    </div>
  );
}
