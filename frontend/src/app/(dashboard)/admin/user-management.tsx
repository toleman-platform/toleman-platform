"use client";

import { useEffect, useState } from "react";
import { api, AuthUser } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SkeletonList } from "@/components/ui/skeleton";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";

const ROLES = ["admin", "user", "viewer", "developer", "security_engineer"];

export function UserManagement() {
  const [users, setUsers] = useState<AuthUser[] | null>(null);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Issue #118: both actions below used to apply instantly with no
  // confirmation, a bare red "Delete" link, and a role `<select>` that
  // fired `onRoleChange` on every `onChange`, including an accidental
  // escalation to admin (global, bypasses all workspace scoping). Both now
  // route through the shared `ConfirmDialog` instead of mutating on click.
  const [pendingDelete, setPendingDelete] = useState<AuthUser | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [pendingRoleChange, setPendingRoleChange] = useState<{ user: AuthUser; newRole: string } | null>(null);
  const [changingRole, setChangingRole] = useState(false);

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

  function requestRoleChange(u: AuthUser, newRole: string) {
    if (newRole === u.role) return;
    // Only admin escalation needs a confirmation gate (per #118), it's a
    // global role that bypasses all workspace-scoped permissions, unlike
    // moving between the other four roles.
    if (newRole === "admin") {
      setPendingRoleChange({ user: u, newRole });
      return;
    }
    applyRoleChange(u.id, newRole);
  }

  async function applyRoleChange(id: number, newRole: string) {
    await api.updateUserRole(id, newRole);
    refresh();
  }

  async function confirmRoleChange() {
    if (!pendingRoleChange) return;
    setChangingRole(true);
    try {
      await applyRoleChange(pendingRoleChange.user.id, pendingRoleChange.newRole);
    } finally {
      setChangingRole(false);
      setPendingRoleChange(null);
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      await api.deleteUser(pendingDelete.id);
      refresh();
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-border bg-card">
        <CardContent className="px-4 py-4">
          {/* One row on desktop, two columns on small screens: at 390px the
              fixed grid-cols-4 squeezed all four controls onto one line and
              clipped their placeholders to "Passw" / "use". */}
          <form onSubmit={onCreate} className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Input className="bg-secondary" placeholder="Name" aria-label="New user name" value={name} onChange={(e) => setName(e.target.value)} required />
            <Input className="bg-secondary" placeholder="Email" aria-label="New user email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            <Input className="bg-secondary" placeholder="Password" aria-label="New user password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <select
              className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              aria-label="New user role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <Button type="submit" disabled={submitting} className="col-span-2 self-start md:col-span-4">
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
            {/* Wraps rather than overflowing: this row used to run the role
                control and Delete straight off the right edge of the card on
                a phone, clipping both and the user's email with them. */}
            <CardContent className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-3">
              <div className="min-w-0">
                <div className="font-medium text-foreground">{u.name}</div>
                <div className="truncate text-xs text-muted-foreground">{u.email}</div>
              </div>
              <div className="flex items-center gap-2">
                {/* The role `<select>` already displays the current role; the
                    Badge that used to sit beside it repeated the identical
                    value (it can never differ; the select is controlled
                    straight off `u.role`) and left the Delete column ragged,
                    since each role string is a different width. */}
                <select
                  className="rounded-md border border-input bg-secondary px-2 py-1 text-xs text-foreground"
                  aria-label={`Role for ${u.name}`}
                  value={u.role}
                  onChange={(e) => requestRoleChange(u, e.target.value)}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <Button size="sm" variant="ghost" className="text-destructive" onClick={() => setPendingDelete(u)}>
                  Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      )}

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete user"
        description={
          pendingDelete ? (
            <>
              Permanently delete <span className="font-medium text-foreground">{pendingDelete.name}</span> (
              {pendingDelete.email})? This cannot be undone.
            </>
          ) : null
        }
        confirmLabel="Delete"
        tone="destructive"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setPendingDelete(null)}
      />

      <ConfirmDialog
        open={pendingRoleChange !== null}
        title="Grant admin access"
        description={
          pendingRoleChange ? (
            <>
              Make <span className="font-medium text-foreground">{pendingRoleChange.user.name}</span> a global admin?
              Admins bypass all workspace-scoped permissions and can manage every workspace, user, and
              platform setting.
            </>
          ) : null
        }
        confirmLabel="Grant admin"
        tone="default"
        loading={changingRole}
        onConfirm={confirmRoleChange}
        onCancel={() => setPendingRoleChange(null)}
      />
    </div>
  );
}
