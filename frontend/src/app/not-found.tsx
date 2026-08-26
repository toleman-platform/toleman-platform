import Link from "next/link";
import { Shield, Compass } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";

// App-wide 404 (Next.js App Router convention: rendered for any unmatched
// route). Mirrors the login page's branding shell (Toleman Shield mark in a
// rounded primary/10 tile + wordmark) since a bare Next.js default 404 has
// no nav/branding/way back into the app (#126) -- reuses the same dark
// theme tokens from globals.css rather than introducing new colors.
export default function NotFound() {
  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background p-4">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 h-96 w-96 rounded-full bg-primary/5 blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 h-96 w-96 rounded-full bg-chart-5/5 blur-3xl" />
      </div>
      <Card className="relative z-10 w-full max-w-md border-border bg-card">
        <CardHeader className="items-center gap-4 pb-2">
          <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <Shield className="h-8 w-8" />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">Toleman</h1>
            <p className="text-sm text-muted-foreground">DevSecOps Vulnerability Management</p>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          <div className="flex flex-col items-center gap-3 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 text-primary">
              <Compass className="h-6 w-6" />
            </div>
            <div className="flex flex-col gap-1">
              <p className="text-4xl font-bold tracking-tight text-foreground">404</p>
              <p className="text-sm font-semibold text-foreground">Page not found</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                The page you&apos;re looking for doesn&apos;t exist or may have been moved.
              </p>
            </div>
            <Button asChild className="mt-2 w-full">
              <Link href="/">Back to Dashboard</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
