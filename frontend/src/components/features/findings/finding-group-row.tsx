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
import { AlertBanner } from "@/components/ui/alert-banner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useWriteAction } from "@/hooks/use-write-action";
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
  onInspect,
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
  /**
   * Open one member finding's full detail.
   *
   * Grouping collapsed the row down to what a *decision* needs, and in doing
   * so it cut off the route to what a single finding needs: the description,
   * the NVD/OSV enrichment (CVE, CWE, CVSS, fix versions), the suggested fix
   * and Raise-PR action, per-finding triage, and the link into the repo at the
   * offending line. All of that still exists in FindingDetailDrawer -- after
   * the grouped view became the default, nothing on the page reached it any
   * more without switching to `?view=flat`.
   */
  onInspect?: (finding: Finding) => void;
}) {
  const [now] = useState(() => Date.now());
  const [expanded, setExpanded] = useState(false);
  const [members, setMembers] = useState<Finding[] | null>(null);
  const [memberTotal, setMemberTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  // One click here dispatches a write against every member of the group — up
  // to MEMBER_FETCH_CAP findings. It used to have no `catch`, so that click
  // failing looked exactly like it succeeding: buttons back, row unchanged,
  // nothing said. See use-write-action.ts.
  const triageAction = useWriteAction("Group triage failed");
  const submitting = triageAction.submitting;

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
    // API.
    //
    // Ungrouped rows fetch too, even though the answer is a single finding.
    // They used to skip it and render only a sentence explaining why they are
    // not collapsed -- which meant a leaked credential, the highest-severity
    // thing this page shows, was the one row you could not open.
    if (!next || members !== null) return;
    await loadMembers();
  }

  async function triageGroup(toState: string) {
    // One rationale recorded against every member, which is both fewer clicks
    // and a better audit trail than the same sentence retyped a dozen times.
    const ids = members?.map((m) => m.id) ?? [];
    if (ids.length === 0 || truncated) return;
    await triageAction.run(async () => {
      await api.bulkTriage(ids, toState, reason);
      setReason("");
      // The members just triaged may no longer match the active filters, and
      // the cached list would otherwise keep showing them with their old
      // states -- a second click would then re-triage findings already in that
      // state. Dropped so the next expand re-reads the truth.
      //
      // All of this is now reached only on success, which matters more here
      // than anywhere else on the page: collapsing the row and dropping the
      // member cache after a *failed* write is the single most convincing way
      // to tell someone their triage went through when it did not.
      setMembers(null);
      setMemberTotal(0);
      setExpanded(false);
      onTriaged?.();
    });
  }

  return (
    // core M11: `role="row"` on the row, `role="cell"` on each of its
    // columns below, so a screen reader's table navigation (arrow keys
    // between cells) works here and each cell is announced against the
    // `columnheader`s in FindingsGroupsList's header row -- "Severity: High",
    // not an unlabelled fragment of a giant flattened string. That is also
    // *why* this can no longer be one `<button>` wrapping the whole row (see
    // the toggle button below, core M12): a button's subtree is flattened to
    // its accessible name, which is exactly what would erase the per-cell
    // structure this item exists to add. The two defects shared one cause.
    <div className={cn("border-l-4 border-b border-border bg-card", SEVERITY_BORDER_COLOR[group.severity])}>
      {/* `role="row"` sits here, on the one-line content only, so its
          children are exactly the six `role="cell"`s below and nothing
          else -- the expanded members panel is a sibling below, outside the
          row, the same way a real table's detail row is never itself a cell
          of the row it discloses. */}
      <div role="row" className="flex items-center gap-3 px-3 py-2 hover:bg-secondary/50">
        <div role="cell" className="flex w-3.5 shrink-0 items-center justify-center">
          {/* core M12: this button's accessible name is now "Expand/Collapse
              <subject> (<tool>)" -- naming the row, not concatenating every
              fact rendered beside it (severity, path, finding count, age,
              signal badges). The old giant button's implicit name read all
              of that as one 20-word run-on; a screen reader user could not
              tell two rows apart without listening to each one in full. */}
          <button
            type="button"
            onClick={toggle}
            aria-expanded={expanded}
            aria-label={`${expanded ? "Collapse" : "Expand"} ${groupSubject(group)} (${group.tool})`}
            className="flex items-center justify-center rounded p-0.5 outline-none hover:bg-secondary focus-visible:ring-ring/50 focus-visible:ring-[3px]"
          >
            <ChevronRight
              aria-hidden="true"
              className={cn(
                "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform motion-reduce:transition-none",
                expanded && "rotate-90 text-foreground",
                !group.grouped && "invisible",
              )}
            />
          </button>
        </div>

        <div role="cell" className="shrink-0">
          <Badge
            variant="outline"
            className={cn("px-1.5 py-0 text-[10px] font-bold uppercase tracking-wide", SEVERITY_COLOR[group.severity])}
          >
            {group.severity}
          </Badge>
        </div>

        <div role="cell" className="flex min-w-0 flex-1 flex-col">
          <span className="truncate font-mono text-[13px] font-medium text-foreground">
            {groupSubject(group)}
            <span className="ml-2 font-sans font-normal text-muted-foreground">{group.tool}</span>
          </span>
          <span className="truncate text-[11px] text-muted-foreground">
            {targetName ? `${targetName} · ` : ""}
            {group.file_count > 1 ? `${group.file_count} files` : group.representative_file_path}
            {group.target_count > 1 ? ` · ${group.target_count} targets` : ""}
          </span>
        </div>

        <div role="cell" className="shrink-0 text-right font-mono text-[13px] font-semibold tabular-nums text-foreground">
          {group.finding_count}
          {group.grouped && group.finding_count > 1 && (
            <span className="ml-1 text-[10px] font-normal text-muted-foreground">rows</span>
          )}
        </div>

        <div role="cell" className="hidden shrink-0 md:block">
          <GroupSignals group={group} />
        </div>

        <div role="cell" className="hidden w-12 shrink-0 text-right font-mono text-[11px] tabular-nums text-muted-foreground lg:block">
          {formatAge(age)}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border bg-secondary/30 px-3 py-2 pl-10">
          {/* Ungrouped categories (Secrets, Malicious Package) render their single
              finding here with no explanation of why they are not collapsed --
              that reasoning is a property of the code, not something the reader
              needs on screen. See UNGROUPED_CATEGORIES in app/core/grouping.py. */}
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
                  <li key={m.id} className="border-b border-border/60 last:border-b-0">
                    <button
                      type="button"
                      onClick={() => onInspect?.(m)}
                      className="flex w-full items-center gap-3 py-1 text-left font-mono text-[11px] text-muted-foreground hover:bg-secondary/60"
                    >
                      <span className="min-w-0 flex-1 truncate text-foreground underline decoration-dotted underline-offset-2">
                        {m.title}
                      </span>
                      <span className="shrink-0">#{m.id}</span>
                      <span className="hidden shrink-0 sm:block">{m.file_path}</span>
                    </button>
                  </li>
                ))}
              </ul>

              {truncated && (
                <p className="mt-2 text-xs text-destructive">
                  Showing {members.length} of {memberTotal}. Narrow the filters to triage this group.
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

              {/* The row stays expanded on failure (see triageGroup), so this
                  sits directly under the buttons that produced it, with the
                  member list it would have acted on still on screen. */}
              {triageAction.error && (
                <AlertBanner tone="critical" title="Group triage failed" className="mt-2">
                  {/* As in findings-list.tsx: the request not completing is
                      not evidence that nothing was written. */}
                  {triageAction.error} The change was not confirmed, so some of these{" "}
                  {members.length} findings may not have been updated. Reload to see their
                  current states before retrying.
                </AlertBanner>
              )}
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
