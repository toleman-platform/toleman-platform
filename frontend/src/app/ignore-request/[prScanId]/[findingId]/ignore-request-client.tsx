"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { api, ApiError, IgnoreStatus, NetworkError } from "@/lib/api";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BrandMark } from "@/components/brand-mark";
import { IGNORE_STATUS_COLOR } from "@/lib/severity";
import { LINK_IGNORE_REASON } from "@/components/pr-guardrail-log";

// A "request ignore" link posted in a PR Guardrail comment used to point at
// /pr-history, the full dashboard page: heavy sidebar layout, a live
// GitHub-PRs fetch, the whole PR Audit log for the target -- all of it
// blocking on-screen feedback for an action that has nothing to do with any
// of that. The user just wants the one thing they clicked for: did the
// ignore request go through. This route is a dedicated, minimal page (no
// (dashboard) layout, no unrelated fetches) so a click on that link lands
// directly on "Requested" (or whatever this finding's actual state already
// is) as fast as the one API call it needs allows, instead of surfacing as
// a slow, unrelated-looking page mid-load.
type State =
  | { phase: "loading" }
  | { phase: "submitting" }
  | { phase: "done"; status: IgnoreStatus; requestedBy?: string; reviewedBy?: string }
  | { phase: "not-found" }
  | { phase: "error"; message: string };

const STATUS_LABEL: Record<IgnoreStatus, string> = {
  none: "Not requested",
  requested: "Requested — pending security review",
  approved: "Approved",
  rejected: "Rejected",
};

export function IgnoreRequestClient({ prScanId, findingId }: { prScanId: number; findingId: number }) {
  const [state, setState] = useState<State>({ phase: "loading" });

  useEffect(() => {
    async function run() {
      let findings;
      try {
        findings = await api.getPrGuardrailFindings(prScanId);
      } catch (e) {
        setState({ phase: "error", message: describeError(e) });
        return;
      }
      const finding = findings.find((f) => f.id === findingId);
      if (!finding) {
        setState({ phase: "not-found" });
        return;
      }
      if (finding.ignore_status !== "none") {
        // Already requested/approved/rejected (a re-clicked or stale link):
        // show the real state rather than resubmitting, which would wipe
        // out a security reviewer's already-made decision (see
        // submit_ignore_request's ignore_reviewed_by/at reset).
        setState({
          phase: "done",
          status: finding.ignore_status,
          requestedBy: finding.ignore_requested_by || undefined,
          reviewedBy: finding.ignore_reviewed_by || undefined,
        });
        return;
      }
      setState({ phase: "submitting" });
      try {
        const updated = await api.requestIgnoreFinding(findingId, LINK_IGNORE_REASON);
        setState({ phase: "done", status: updated.ignore_status, requestedBy: updated.ignore_requested_by || undefined });
      } catch (e) {
        setState({ phase: "error", message: describeError(e) });
      }
    }
    run();
    // Runs once per mount; this page is keyed by prScanId/findingId in the URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="relative z-10 w-full max-w-md border-border bg-card">
        <CardHeader className="items-center gap-4 pb-2">
          <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-accent">
            <BrandMark size={30} />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-bold tracking-tight text-foreground">Request Ignore</h1>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col items-center gap-3 pt-4 pb-2 text-center">
          {(state.phase === "loading" || state.phase === "submitting") && (
            <>
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {state.phase === "loading" ? "Looking up this finding..." : "Submitting your ignore request..."}
              </p>
            </>
          )}

          {state.phase === "done" && (
            <>
              <CheckCircle2 className="h-8 w-8 text-chart-5" />
              <Badge variant="outline" className={IGNORE_STATUS_COLOR[state.status] || "text-muted-foreground"}>
                {STATUS_LABEL[state.status]}
              </Badge>
              {state.status === "requested" && (
                <p className="text-sm text-muted-foreground">
                  A security reviewer still needs to approve this before the finding is actually ignored.
                </p>
              )}
              {(state.status === "approved" || state.status === "rejected") && state.reviewedBy && (
                <p className="text-sm text-muted-foreground">Reviewed by {state.reviewedBy}.</p>
              )}
            </>
          )}

          {state.phase === "not-found" && (
            <>
              <XCircle className="h-8 w-8 text-destructive" />
              <p className="text-sm text-muted-foreground">
                This finding could not be found. It may have been resolved or the scan re-run since this link was posted.
              </p>
            </>
          )}

          {state.phase === "error" && (
            <>
              <XCircle className="h-8 w-8 text-destructive" />
              <p className="text-sm text-destructive">{state.message}</p>
            </>
          )}

          <Link href="/pr-history" className="mt-2 text-xs text-muted-foreground underline hover:text-foreground">
            Go to PR History
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}

function describeError(e: unknown): string {
  if (e instanceof NetworkError) return e.message;
  if (e instanceof ApiError) return e.message;
  return "Something went wrong requesting the ignore.";
}
