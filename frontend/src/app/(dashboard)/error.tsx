"use client";

import { useEffect, useState } from "react";
import { Shield, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

// (#235, UI-03) Next's own fallback for an uncaught error during a Server
// Component render was the entire complaint: "This page couldn't load, A
// server error occurred", digest only, no nav, no explanation, and no way
// back short of a manual reload. A routine backend restart (a few seconds
// of connection-refused while a redeployed container comes back up) used
// to land here and blank the app for anyone whose render happened to land
// in that window.
//
// What this can and cannot say, and why the copy below is deliberately
// non-committal about cause: Next.js strips the real Error's message/name
// before it reaches a Client Component error boundary in a production
// build (only `digest` survives, for correlating with server logs); a
// documented security measure so a thrown error can't leak server-side
// detail to the browser. That means this boundary structurally cannot say
// "this was specifically the backend being briefly unavailable" the way a
// client-side catch of NetworkError (see lib/api.ts) can. What it can do:
// retry automatically once, since the one failure mode this is actually
// aimed at (a brief restart) is very likely to have resolved a couple
// of seconds later; and offer a manual retry that doesn't ask for a full
// page reload.
//
// The real fix for the common case is upstream of this file entirely:
// fetchWithConnectionRetry (lib/api.ts) now retries a connection-level
// failure before it ever throws, so most transient restarts never reach
// this boundary at all. This is the backstop for what that doesn't catch.
export default function DashboardError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const [autoRetried, setAutoRetried] = useState(false);

  useEffect(() => {
    if (autoRetried) return;
    const timer = setTimeout(() => {
      setAutoRetried(true);
      reset();
    }, 2000);
    return () => clearTimeout(timer);
  }, [autoRetried, reset]);

  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="relative flex min-h-[70vh] items-center justify-center p-4">
      <Card className="relative z-10 w-full max-w-md border-border bg-card">
        <CardHeader className="items-center gap-4 pb-2">
          <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-destructive/10 text-destructive">
            <Shield className="h-8 w-8" />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">Toleman</h1>
            <p className="text-sm text-muted-foreground">DevSecOps Vulnerability Management</p>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          <div className="flex flex-col items-center gap-3 text-center">
            <div className="flex flex-col gap-1">
              <p className="text-sm font-semibold text-foreground">This page couldn&apos;t load</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                {autoRetried
                  ? "Still having trouble reaching the server. It may be restarting, try again in a moment."
                  : "This is often a brief backend restart. Retrying automatically…"}
              </p>
              {error.digest && (
                <p className="mt-1 font-mono text-xs text-muted-foreground/70">Reference: {error.digest}</p>
              )}
            </div>
            <Button onClick={() => reset()} className="mt-2 w-full">
              <RefreshCw className="mr-2 h-4 w-4" />
              Try again
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
