"use client";

import { Button } from "@/components/ui/button";

/** Full-reload retry action for server-component pages whose data fetch
 * failed — a plain `location.reload()` is the right recovery there (there's
 * no client-side re-fetch to call, unlike a "use client" list component
 * that can just re-run its own effect). */
export function ReloadButton({ label = "Try again" }: { label?: string }) {
  return (
    <Button size="sm" variant="outline" onClick={() => window.location.reload()}>
      {label}
    </Button>
  );
}
