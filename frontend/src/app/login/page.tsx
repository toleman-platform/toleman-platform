"use client";

import { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { BrandMark } from "@/components/brand-mark";
import { api, ApiError, NetworkError } from "@/lib/api";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.login(email, password);
      router.push(searchParams.get("next") || "/");
      router.refresh();
    } catch (e) {
      // A wrong password (401) is the only case that should say "Invalid
      // email or password", collapsing every failure into that message
      // (the previous bare `catch { setError(...) }`) made a 429 rate limit,
      // a network error, or a 500 all read as a typo, which is actively
      // misleading when the real cause is something the user can't fix by
      // retyping their password.
      if (e instanceof NetworkError) {
        // The request never arrived, so the server never judged these
        // credentials; saying they're wrong would be a guess, and the
        // wrong one (BLD-03).
        setError(e.message);
      } else if (e instanceof ApiError && e.status !== 401) {
        setError(e.message);
      } else {
        setError("Invalid email or password.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="page-enter relative z-10 w-full max-w-[26rem] gap-4 border-border/60 bg-card py-8 shadow-[var(--shadow-raised)]">
        <CardHeader className="items-center gap-4 pb-2">
          <div className="flex h-16 w-16 items-center justify-center justify-self-center rounded-[1.1rem] bg-accent">
            <BrandMark size={30} />
          </div>
          <div className="text-center">
            <h1 className="text-3xl font-semibold tracking-[-0.03em] text-foreground">Toleman</h1>
            <p className="text-sm text-muted-foreground">DevSecOps Vulnerability Management</p>
          </div>
        </CardHeader>
        <CardContent className="pt-4">
          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="email" className="text-foreground">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="bg-secondary text-foreground placeholder:text-muted-foreground"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="password" className="text-foreground">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="bg-secondary pr-10 text-foreground placeholder:text-muted-foreground"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" size="lg" disabled={loading} className="w-full">
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Sign In
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
