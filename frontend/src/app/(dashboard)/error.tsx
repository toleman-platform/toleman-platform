"use client";

import { useEffect, useState } from "react";
import { Shield, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

// Production Server Component errors expose only a digest to this client boundary, so
// do not infer a specific cause. Retry once automatically and offer manual retry
// without full reload. Connection-level retries upstream handle most transient backend
// restarts; this boundary is the fallback.
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
