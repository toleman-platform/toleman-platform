---
sidebar_position: 1
---

# Users & Roles

Rikugan uses a two-layer role system.

## Global role

Every `User` has one global `UserRole`: `admin`, `user`, `viewer`, `developer`, or `security_engineer`. **Admins bypass all workspace scoping** — they see every workspace's data with no filtering.

Manage users: **Admin → User Management** tab, or `/api/admin` (admin-only).

## Workspace role

`WorkspaceMembership` (user_id, workspace_id, `WorkspaceRole`) layers a **workspace-scoped** role on top of the global one. Non-admin visibility on every GET/list endpoint over workspace-owned resources (targets, findings, scans, etc.) is filtered through `accessible_workspace_ids()` — a user only sees workspaces they're a member of.

Assign roles: **Admin → Workspace Roles** tab, or `/api/admin/workspace-roles`.

## Auth

Login is pbkdf2-hashed password + HMAC-signed session cookie — no external auth service (`app/core/security.py`). Route protection on the frontend lives in `src/proxy.ts`.

The seeded admin account (`ADMIN_EMAIL`/`ADMIN_PASSWORD` in backend `.env`, default `admin@rikugan.io` / `changeme123`) is created on first backend startup — **change the password before any non-local use.**
