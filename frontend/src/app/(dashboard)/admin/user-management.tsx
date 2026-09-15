"use client";

import { useState } from "react";
import { api, AuthUser } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { AsyncContent } from "@/components/ui/async-content";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";

// M18: both `<select>`s below used to render these values verbatim
// (`security_engineer` as an option's own text), so the raw snake_case enum
// -- not a label meant for anyone to read -- was the only thing on screen.
// `value` stays the wire format the API expects; `label` is the only thing
// this file adds.
const ROLES: { value: string; label: string }[] = [
  { value: "admin", label: "Admin" },
  { value: "user", label: "User" },
  { value: "viewer", label: "Viewer" },
  { value: "developer", label: "Developer" },
  { value: "security_engineer", label: "Security engineer" },
];

export function UserManagement() {
  // Was `api.users().then(setUsers)` with no `.catch`, so a failed read left
  // the skeleton up forever with no error and no retry.
  const usersState = useAsyncData<AuthUser[]>(() => api.users());
  const refresh = usersState.refetch;
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
  const [roleError, setRoleError] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

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
    void applyRoleChange(u.id, newRole);
  }

  // The un-awaited, un-caught version of this left the controlled `<select>`
  // showing whichever role the server had just rejected: nothing re-rendered
  // it, so the dropdown claimed a role the user did not have. Refresh runs on
  // both paths so the row always ends up showing stored state.
  async function applyRoleChange(id: number, newRole: string): Promise<boolean> {
    setRoleError(null);
    try {
      await api.updateUserRole(id, newRole);
      return true;
    } catch (e) {
      setRoleError(e instanceof Error ? e.message : "failed to change role");
      return false;
    } finally {
      refresh();
    }
  }

  async function confirmRoleChange() {
    if (!pendingRoleChange) return;
    setChangingRole(true);
    try {
      const ok = await applyRoleChange(pendingRoleChange.user.id, pendingRoleChange.newRole);
      if (ok) setPendingRoleChange(null);
    } finally {
      setChangingRole(false);
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deleteUser(pendingDelete.id);
      setPendingDelete(null);
      refresh();
    } catch (e) {
      // Used to close the dialog with the row still present and nothing said.
      setDeleteError(e instanceof Error ? e.message : "failed to delete user");
    } finally {
      setDeleting(false);
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
            <Input className="bg-secondary" placeholder="Password" aria-label="New user password" type="password" autoComplete="new-password" spellCheck={false} value={password} onChange={(e) => setPassword(e.target.value)} required />
            <select
              className="rounded-md border border-input bg-secondary px-3 py-2 text-sm text-foreground"
              aria-label="New user role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              {ROLES.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
            <Button type="submit" disabled={submitting} className="col-span-2 self-start md:col-span-4">
              {submitting ? "Creating…" : "Create User"}
            </Button>
          </form>
          {error && <p role="alert" className="mt-2 text-xs text-destructive">{error}</p>}
        </CardContent>
      </Card>

      {roleError && (
        <p role="alert" className="text-xs text-destructive">
          {roleError}
        </p>
      )}

      <AsyncContent
        state={usersState}
        itemNoun="users"
        errorTitle="Couldn't load the user list"
        emptyTitle="No users yet"
        skeletonCount={3}
        className="flex flex-col gap-2"
      >
        {(users) => (
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
                    <option key={r.value} value={r.value}>
                      {r.label}
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
      </AsyncContent>

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete user"
        description={
          pendingDelete ? (
            <>
              Permanently delete <span className="font-medium text-foreground">{pendingDelete.name}</span> (
              {pendingDelete.email})? This cannot be undone.
              {deleteError && <span className="mt-2 block text-destructive">{deleteError}</span>}
            </>
          ) : null
        }
        confirmLabel="Delete"
        tone="destructive"
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => {
          setDeleteError(null);
          setPendingDelete(null);
        }}
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
              {roleError && <span className="mt-2 block text-destructive">{roleError}</span>}
            </>
          ) : null
        }
        confirmLabel="Grant admin"
        tone="default"
        loading={changingRole}
        onConfirm={confirmRoleChange}
        onCancel={() => {
          setRoleError(null);
          setPendingRoleChange(null);
        }}
      />
    </div>
  );
}
