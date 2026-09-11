"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { api, AuthEventType } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SkeletonList } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ui/error-state";
import { EmptyState } from "@/components/ui/empty-state";
import { ActivityPagination, pageSizeFromParams } from "@/components/activity-pagination";
import { AUTH_EVENT_COLOR, AUTH_EVENT_LABEL } from "@/lib/severity";
import { ShieldAlert } from "lucide-react";

const EVENT_TYPES: AuthEventType[] = [
  "login_success",
  "login_failed",
  "logout",
  "password_changed",
  "role_changed",
  "workspace_role_changed",
  "workspace_role_removed",
];

const SELECT_CLASS =
  "h-8 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

// Admin-only: who logged in/out (and from where), who changed their
// password, and who changed whose permissions -- app.models.models.
// AuthAuditLog via GET /api/audit/security-log, distinct from the
// findings-triage Audit Log page (visible to any authenticated user).
// URL-backed filters/pagination (?event_type=&email=&page=&page_size=),
// same convention as the rest of this codebase's paginated lists, nested
// under the Admin page's own ?tab= param without conflicting with it.
export function SecurityLog() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const eventType = (searchParams.get("event_type") as AuthEventType | null) ?? undefined;
  const email = searchParams.get("email") ?? undefined;
  const page = Math.max(1, Number(searchParams.get("page")) || 1);
  const pageSize = pageSizeFromParams(searchParams.get("page_size") ?? undefined);

  const {
    data: result,
    error: loadError,
    isInitialLoading,
  } = useAsyncData(
    () => api.securityAuditLog({ event_type: eventType, email, page, page_size: pageSize }),
    { deps: [eventType, email, page, pageSize] },
  );
  const error = loadError?.message ?? null;

  function updateParam(key: string, value: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (value) params.set(key, value);
    else params.delete(key);
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  const hasFilters = Boolean(eventType || email);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold text-foreground">Security Log</h2>
        <p className="text-sm text-muted-foreground">
          Login/logout activity, password changes, and permission changes across every user.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card p-3">
        <select
          aria-label="Filter by event type"
          className={SELECT_CLASS}
          value={eventType ?? ""}
          onChange={(e) => updateParam("event_type", e.target.value)}
        >
          <option value="">All events</option>
          {EVENT_TYPES.map((t) => (
            <option key={t} value={t}>
              {AUTH_EVENT_LABEL[t]}
            </option>
          ))}
        </select>
        <input
          aria-label="Filter by user email"
          placeholder="Filter by user email..."
          className="h-8 min-w-[220px] flex-1 rounded-md border border-input bg-secondary px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          defaultValue={email ?? ""}
          onKeyDown={(e) => {
            if (e.key === "Enter") updateParam("email", e.currentTarget.value.trim());
          }}
          onBlur={(e) => updateParam("email", e.currentTarget.value.trim())}
        />
        {hasFilters && (
          <button
            onClick={() => router.push(pathname)}
            className="text-xs text-muted-foreground underline hover:text-foreground"
          >
            Clear filters
          </button>
        )}
      </div>

      {error && <ErrorState description={error} />}
      {isInitialLoading && !error && <SkeletonList count={5} />}

      {result && (
        <>
          <ActivityPagination total={result.total} page={page} pageSize={pageSize} position="top" />

          <div className="flex flex-col gap-2">
            {result.items.map((e) => (
              <Card key={e.id} className="border-border bg-card">
                <CardContent className="px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={`shrink-0 px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${AUTH_EVENT_COLOR[e.event_type] || "text-muted-foreground"}`}
                        >
                          {AUTH_EVENT_LABEL[e.event_type] || e.event_type}
                        </Badge>
                        <span className="truncate text-sm font-medium text-foreground">
                          {e.target_email && e.target_email !== e.actor
                            ? `${e.actor} -> ${e.target_email}`
                            : e.actor}
                        </span>
                      </div>
                      {(e.detail || e.ip_address) && (
                        <div className="mt-1 truncate text-xs text-muted-foreground">
                          {e.detail}
                          {e.detail && e.ip_address ? " · " : ""}
                          {e.ip_address && `from ${e.ip_address}`}
                        </div>
                      )}
                    </div>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {new Date(e.created_at).toLocaleString()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
            {result.items.length === 0 && (
              <EmptyState
                icon={ShieldAlert}
                title={hasFilters ? "No events match these filters" : "No security events yet"}
                description={
                  hasFilters
                    ? "Try widening your event type or user filter."
                    : "Login, logout, and permission-change activity will show up here."
                }
              />
            )}
          </div>

          {result.total > 0 && <ActivityPagination total={result.total} page={page} pageSize={pageSize} />}
        </>
      )}
    </div>
  );
}
