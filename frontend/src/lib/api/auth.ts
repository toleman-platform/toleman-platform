import { jsonFetch } from "./client";
import type { AuthUser, NotificationPreference } from "@/types";

/**
 * Authenticates a user with email and password credentials.
 * Sets the `toleman_session` HTTP-only cookie upon success.
 */
export function login(email: string, password: string): Promise<AuthUser> {
  return jsonFetch<AuthUser>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

/**
 * Terminates the current session and clears the session cookie.
 */
export function logout(): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>("/api/auth/logout", { method: "POST" });
}

/**
 * Retrieves the currently authenticated user's profile and permissions.
 */
export function me(): Promise<AuthUser> {
  return jsonFetch<AuthUser>("/api/auth/me");
}

/**
 * Updates the current user's profile display name.
 */
export function updateMe(name: string): Promise<AuthUser> {
  return jsonFetch<AuthUser>("/api/auth/me", {
    method: "PATCH",
    body: JSON.stringify({ name }),
  });
}

/**
 * Changes the current user's password.
 */
export function changePassword(currentPassword: string, newPassword: string): Promise<{ ok: boolean }> {
  return jsonFetch<{ ok: boolean }>("/api/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

/**
 * Fetches the user's notification preferences across channels and event types.
 */
export function notificationPreferences(): Promise<NotificationPreference[]> {
  return jsonFetch<NotificationPreference[]>("/api/notification-preferences");
}

/**
 * Updates the user's notification preferences.
 */
export function setNotificationPreferences(preferences: NotificationPreference[]): Promise<NotificationPreference[]> {
  return jsonFetch<NotificationPreference[]>("/api/notification-preferences", {
    method: "PUT",
    body: JSON.stringify({ preferences }),
  });
}
