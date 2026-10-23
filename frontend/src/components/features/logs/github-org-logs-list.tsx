import { Github } from "lucide-react";
import { OrgActivityEvent } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorState } from "@/components/ui/error-state";
import { ReloadButton } from "@/components/reload-button";
import { ActivityPagination } from "@/components/ui/activity-pagination";
import { Timestamp } from "@/components/ui/timestamp";

export function GithubOrgLogsList({
  events,
  total,
  page,
  pageSize,
  failed = false,
}: {
  events: OrgActivityEvent[];
  total: number;
  page: number;
  pageSize: number;
  /**
   * True when the events request failed, allowing the shared list to distinguish
   * failure from a successful empty response. Defaults false for compatibility with
   * callers that branch to ErrorState themselves.
   */
  failed?: boolean;
}) {
  if (failed) {
    return (
      <ErrorState description="GitHub org activity couldn't be loaded from the API." action={<ReloadButton />} />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />
      <div className="flex flex-col gap-2">
        {events.map((e) => (
          // sha is a git commit hash: content-addressed and already unique
          // per repo. Paired with target_id (not sha alone) in case the same
          // commit is ever visible under two connected targets, e.g. a fork.
          // `key={i}` previously relabeled every row below an insert/delete
          // instead of tracking the commit it was actually rendering.
          <Card key={`${e.target_id}-${e.sha}`} className="border-border bg-card">
            <CardContent className="flex items-center justify-between px-4 py-2.5">
              <div>
                <a href={safeHref(e.url)} target="_blank" rel="noreferrer" className="text-sm text-foreground hover:underline">
                  {e.message}
                </a>
                <div className="text-xs text-muted-foreground">
                  {e.author} · {e.sha}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline">{e.target}</Badge>
                {e.date && <Timestamp value={e.date} className="text-xs text-muted-foreground" />}
              </div>
            </CardContent>
          </Card>
        ))}
        {events.length === 0 && (
          <EmptyState
            icon={Github}
            title="No activity found"
            description="Recent commit activity from your integrated repositories will appear here. Try widening your filters."
          />
        )}
      </div>
      <ActivityPagination total={total} page={page} pageSize={pageSize} />
    </div>
  );
}
