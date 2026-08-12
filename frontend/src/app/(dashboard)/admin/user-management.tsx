"use client";

import { useEffect, useState } from "react";
import { api, AuthUser } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SkeletonList } from "@/components/ui/skeleton";

const ROLES = ["admin", "user", "viewer"];

export function UserManagement() {
  const [users, setUsers] = useState<AuthUser[] | null>(null);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function refresh() {
    api.users().then(setUsers);
  }

  useEffect(refresh, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.createUser({ email, name, password, role });
      setEmail("");
      setName("");
      setPassword("");
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create user");
    } finally {
      setSubmitting(false);
    }
  }

  async function onRoleChange(id: number, newRole: string) {
    await api.updateUserRole(id, newRole);
    refresh();
  }

  async function onDelete(id: number) {
    await api.deleteUser(id);
    refresh();
  }

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-border bg-card">
        <CardContent className="px-4 py-4">
          <form onSubmit={onCreate} className="grid grid-cols-4 gap-3">
            <Input className="bg-secondary" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required />
            <Input className="bg-secondary" placeholder="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            <Input className="bg-secondary" placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <select
              className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <Button type="submit" disabled={submitting} className="col-span-4 self-start">
              {submitting ? "Creating..." : "Create User"}
            </Button>
          </form>
          {error && <p className="mt-2 text-xs text-destructive">{error}</p>}
        </CardContent>
      </Card>

      {users === null && <SkeletonList count={3} />}

      {users !== null && (
      <div className="flex flex-col gap-2">
        {users.map((u) => (
          <Card key={u.id} className="border-border bg-card">
            <CardContent className="flex items-center justify-between px-4 py-3">
              <div>
                <div className="font-medium text-foreground">{u.name}</div>
                <div className="text-xs text-muted-foreground">{u.email}</div>
              </div>
              <div className="flex items-center gap-2">
                <select
                  className="rounded-md border border-input bg-secondary px-2 py-1 text-xs text-foreground"
                  value={u.role}
                  onChange={(e) => onRoleChange(u.id, e.target.value)}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <Badge variant="outline">{u.role}</Badge>
                <Button size="sm" variant="ghost" className="text-destructive" onClick={() => onDelete(u.id)}>
                  Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      )}
    </div>
  );
}
