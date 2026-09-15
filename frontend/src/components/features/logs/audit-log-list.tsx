"use client";

import { useState } from "react";
import { ChevronRight, ScrollText } from "lucide-react";
import { AuditEvent } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { ActivityPagination } from "@/components/activity-pagination";
import { Timestamp } from "@/components/ui/timestamp";

/**
 * Issue #123: a single bulk-triage action used to write one FindingStateLog
 * row per finding, so a 30-finding bulk action flooded this feed with 30
 * near-identical cards. The backend now collapses same-batch rows into one
 * item with grouped_count > 1, rendered here as a single card with an
 * "N findings ... ▸ expand" disclosure instead of N separate cards.
 */
function AuditEventCard({ event }: { event: AuditEvent }) {
  const [expanded, setExpanded] = useState(false);
  const isGrouped = event.grouped_count > 1 && !!event.expand;

  return (
    <Card className="border-border bg-card">
      <CardContent className="flex flex-col gap-2 px-4 py-2.5">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            {isGrouped ? (
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                className="flex items-center gap-1.5 text-left text-sm text-foreground hover:underline"
                aria-expanded={expanded}
              >
                <ChevronRight className={`h-3.5 w-3.5 shrink-0 transition-transform ${expanded ? "rotate-90" : ""}`} />
                {event.summary}
              </button>
            ) : (
              <div className="text-sm text-foreground">{event.summary}</div>
            )}
            {event.reason && <div className="text-xs text-muted-foreground">reason: {event.reason}</div>}
          </div>
          <div className="flex shrink-0 items-center gap-2 text-right">
            <Badge variant="outline" className="capitalize">
              {event.type}
            </Badge>
            <span className="text-xs text-muted-foreground">{event.actor}</span>
            <Timestamp value={event.timestamp} className="text-xs text-muted-foreground" />
          </div>
        </div>

        {isGrouped && expanded && (
          <div className="flex flex-col gap-1 border-t border-border pt-2 pl-5">
            {event.expand!.map((item, i) => (
              <div key={`${item.finding_id}-${i}`} className="flex items-center justify-between text-xs text-muted-foreground">
                <span>
                  {item.from_state} &rarr; {item.to_state}
                  {item.title ? `: ${item.title}` : ""}
                </span>
                <Timestamp value={item.timestamp} mode="time" />
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function AuditLogList({
  events,
  total,
  page,
  pageSize,
  failed = false,
}: {
  events: AuditEvent[];
  total: number;
  page: number;
  pageSize: number;
  /**
   * True when the request that produced `events` failed (audit-log/page.tsx
   * passes `auditResult === null` from its `settleOrNull(api.auditLog(...))`).
   *
   * This used to be a decision the *page* made on its own: call this
   * component only on success, render an `ErrorState` itself otherwise. That
   * puts the empty-vs-failed distinction one `if` away from evaporating --
   * on a compliance surface, a caller that forgets the branch (or a future
   * surface that reuses this list without copying it) renders "No audit
   * events found" for a request that never actually answered, which is
   * exactly the false all-clear #77/#465's honesty pass exists to prevent
   * everywhere else. Taking `failed` as a prop instead means the guarantee
   * lives once, in the component every caller already has to use, rather
   * than in every call site's discipline. Defaults to `false` so existing
   * callers that don't pass it keep today's behavior.
   */
  failed?: boolean;
}) {
  if (failed) {
    return (
      <ErrorState description="The audit log couldn't be loaded from the API." action={<ReloadButton />} />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />
      <div className="flex flex-col gap-2">
        {events.map((e) => (
          // No id comes back from the API (AuditEvent is an immutable log
          // row, not a keyed entity) -- timestamp+actor+type+summary is as
          // close to a natural key as the shape allows, and unlike `key={i}`
          // it survives a row being inserted/removed by a page-size or
          // filter change instead of silently relabeling every card below it.
          <AuditEventCard key={`${e.timestamp}|${e.actor}|${e.type}|${e.summary}`} event={e} />
        ))}
        {events.length === 0 && (
          <EmptyState
            icon={ScrollText}
            title="No audit events found"
            description="Triage decisions and scan runs will show up here as they happen. Try widening your filters."
          />
        )}
      </div>
      <ActivityPagination total={total} page={page} pageSize={pageSize} />
    </div>
  );
}
