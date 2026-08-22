import { Github } from "lucide-react";
import { OrgActivityEvent } from "@/lib/api";
import { safeHref } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination } from "@/components/activity-pagination";

export function GithubOrgLogsList({
  events,
  total,
  page,
  pageSize,
}: {
  events: OrgActivityEvent[];
  total: number;
  page: number;
  pageSize: number;
}) {
  return (
    <div className="flex flex-col gap-3">
      <ActivityPagination total={total} page={page} pageSize={pageSize} position="top" />
      <div className="flex flex-col gap-2">
        {events.map((e, i) => (
          <Card key={i} className="border-border bg-card">
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
                <span className="text-xs text-muted-foreground">{e.date ? new Date(e.date).toLocaleString() : ""}</span>
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
