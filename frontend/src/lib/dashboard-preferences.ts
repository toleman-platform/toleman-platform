/**
 * Per-user dashboard widget visibility: which of the widgets in a user's
 * saved layout are actually drawn for them.
 *
 * Two layers, in precedence order:
 *
 *  1. The user's own show/hide choices, stored per user id in this browser.
 *  2. A default derived from the user's platform role, used only while (1)
 *     does not exist.
 *
 * Why this is separate from the saved layout (`GET/PUT /api/dashboard/layout`,
 * issue #69): that endpoint owns layout *composition* -- which widget
 * instances exist and in what order -- and its PUT replaces the whole row.
 * Writing a visibility flip through it would mean a full-layout write on
 * every checkbox click from view mode, on a surface whose known failure mode
 * (see the `layoutFailed` comment in dashboard-board.tsx) is silently
 * overwriting a layout the page never successfully read. Visibility is a
 * view preference with no server-side consumer, so it is kept out of that
 * write path entirely; nothing here can damage server state. The trade-off
 * is that a user's show/hide choices do not follow them to another browser,
 * which is why every read below has to treat "nothing stored" as normal
 * rather than exceptional.
 *
 * Deliberately React-free so it stays importable from anywhere and unit
 * testable without a DOM; the `useSyncExternalStore` wrapper that turns it
 * into a hook lives in components/dashboard/use-widget-visibility.ts.
 */

import type { WidgetId } from "@/types";

/**
 * Every widget id the frontend knows about, as a runtime lookup.
 *
 * Typed as a total record over `WidgetId` on purpose: adding a widget to the
 * union without adding it here is a type error, which is what keeps the
 * role defaults below from silently drifting out of date.
 */
const KNOWN_WIDGET_IDS: Readonly<Record<WidgetId, true>> = {
  kpi_cards: true,
  findings_trend: true,
  cve_timeline: true,
  sla_compliance: true,
  top_risky_repos: true,
  recent_findings: true,
  security_score: true,
  fp_auto_suppressions: true,
  live_scan_activity: true,
  ai_ml_risk: true,
  guardrail_activity: true,
};

/** Narrows an arbitrary stored string back to a widget id we can render. */
export function isWidgetId(value: unknown): value is WidgetId {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(KNOWN_WIDGET_IDS, value);
}

/**
 * The three shapes a first-run dashboard takes. Named for what the reader
 * wants off the screen, not for a job title: the platform's role vocabulary
 * (app.models.models.UserRole) is admin / security_engineer / developer /
 * viewer / user, and several of those map onto the same reading.
 */
export type WidgetDefaultProfile = "leadership" | "engineer" | "overview";

/**
 * Which widgets each profile starts with.
 *
 * These are emphases, not filters. The backend's default layout
 * (app.core.widgets.DEFAULT_WIDGET_ORDER) is seven widgets, and a profile
 * that named only two or three of them would leave a first-time user staring
 * at a nearly empty dashboard -- which is the complaint this feature exists
 * to answer, not a fix for it. So each profile keeps most of the board and
 * drops only what is genuinely not that reader's job.
 *
 * `leadership` keeps posture, trend and concentration of risk, and drops the
 * per-finding triage queue: a reader at this level acts on the aggregate, not
 * on individual findings.
 *
 * `engineer` keeps the work surfaces -- the queue, what is blocking pull
 * requests, what is scanning, where the risk concentrates -- and drops SLA
 * compliance, which is a reporting view. `guardrail_activity` and
 * `live_scan_activity` are not in the backend's default layout, so listing
 * them here only means they are already on for an engineer the moment they
 * are added.
 *
 * `overview` keeps everything in the default layout. Someone without a
 * triage or reporting job has no widget that is clearly not for them, and
 * guessing wrong costs them the information.
 *
 * Ordering within the arrays carries no meaning; widgets are drawn in the
 * saved layout's order, which the user controls through Edit Dashboard.
 */
export const PROFILE_WIDGETS: Readonly<Record<WidgetDefaultProfile, readonly WidgetId[]>> = {
  leadership: [
    "security_score",
    "kpi_cards",
    "sla_compliance",
    "findings_trend",
    "top_risky_repos",
    "cve_timeline",
    "ai_ml_risk",
  ],
  engineer: [
    "security_score",
    "kpi_cards",
    "findings_trend",
    "top_risky_repos",
    "cve_timeline",
    "recent_findings",
    "guardrail_activity",
    "live_scan_activity",
    "fp_auto_suppressions",
    "ai_ml_risk",
  ],
  // Every widget there is, deliberately. Listing them rather than special-
  // casing "hide nothing" keeps the profile a plain data answer to the same
  // question the other two answer, and makes it obvious at review time that
  // nothing was left out by accident.
  overview: [
    "security_score",
    "kpi_cards",
    "sla_compliance",
    "findings_trend",
    "top_risky_repos",
    "cve_timeline",
    "recent_findings",
    "guardrail_activity",
    "live_scan_activity",
    "fp_auto_suppressions",
    "ai_ml_risk",
  ],
};

/**
 * Platform role -> profile. Keys are exactly the values of the backend's
 * `UserRole` enum; anything else resolves to `null` below and is treated as
 * "we do not know enough to hide anything".
 */
export const ROLE_PROFILE: Readonly<Record<string, WidgetDefaultProfile>> = {
  admin: "leadership",
  security_engineer: "leadership",
  developer: "engineer",
  viewer: "overview",
  user: "overview",
};

/**
 * The default widget set for a role, or `null` when the role is unknown or
 * unreadable. `null` is not an empty set: the caller shows everything in
 * that case rather than guessing at a persona.
 */
export function defaultWidgetsForRole(role: string | null | undefined): readonly WidgetId[] | null {
  // hasOwnProperty rather than a truthiness check on the lookup: a role
  // string of "constructor" or "toString" would otherwise find something on
  // Object.prototype and pass.
  if (!role || !Object.prototype.hasOwnProperty.call(ROLE_PROFILE, role)) return null;
  return PROFILE_WIDGETS[ROLE_PROFILE[role]];
}

/** A user's stored show/hide choices: the widgets they turned off. */
export type VisibilityPreference = {
  hidden: readonly WidgetId[];
};

/**
 * What a read of this browser's stored preference produced.
 *
 * `preference: null` with `storageReadable: true` is the ordinary
 * "this user has never changed anything" case. `storageReadable: false` is
 * the browser refusing us storage altogether (private window, site data
 * blocked); both fall back to the role default, but only the second one is
 * worth telling the user about, because in that state their next change
 * will not survive a reload.
 */
export type VisibilitySnapshot = {
  preference: VisibilityPreference | null;
  storageReadable: boolean;
};

const NO_PREFERENCE: VisibilitySnapshot = Object.freeze({ preference: null, storageReadable: true });
const UNREADABLE: VisibilitySnapshot = Object.freeze({ preference: null, storageReadable: false });

const STORAGE_KEY_PREFIX = "toleman-dashboard-widgets";

/**
 * Storage key for one user. Keyed by user id because a shared workstation is
 * normal in this product, and one operator's hidden widgets must not become
 * the next operator's.
 */
export function widgetVisibilityStorageKey(userId: number): string {
  return `${STORAGE_KEY_PREFIX}:${userId}`;
}

// `useSyncExternalStore` compares snapshots with Object.is and re-renders in
// a loop if getSnapshot hands back a fresh object every call, so the parsed
// result is memoised against the exact raw string it came from. Both misses
// ("nothing stored", "storage refused") return module-level frozen
// constants, which are stable for free.
//
// Keyed by storage key rather than a single slot: a single slot is stable
// only while one user is being read, and would thrash -- re-parsing, and so
// returning a fresh object every time -- the moment two readers alternated.
const snapshotCache = new Map<string, { raw: string; snapshot: VisibilitySnapshot }>();

function parsePreference(raw: string): VisibilityPreference | null {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const hidden = (value as { hidden?: unknown }).hidden;
  if (!Array.isArray(hidden)) return null;
  // Unknown ids are dropped rather than kept: a widget that was removed from
  // the catalog would otherwise sit in this list forever, and a malformed
  // entry would be compared against real ids on every render.
  const ids: WidgetId[] = (hidden as unknown[]).filter(isWidgetId);
  return Object.freeze({ hidden: Object.freeze(ids) });
}

/**
 * Reads this browser's stored preference for one user. Never throws: a
 * browser that denies storage, and a key holding something we cannot parse,
 * both come back as "no preference" so the caller falls through to the role
 * default instead of rendering an empty dashboard.
 */
export function readWidgetVisibility(userId: number | null): VisibilitySnapshot {
  if (typeof window === "undefined" || userId === null) return NO_PREFERENCE;
  const key = widgetVisibilityStorageKey(userId);
  let raw: string | null;
  try {
    raw = window.localStorage.getItem(key);
  } catch {
    return UNREADABLE;
  }
  if (raw === null) return NO_PREFERENCE;
  const cached = snapshotCache.get(key);
  if (cached && cached.raw === raw) return cached.snapshot;
  const parsed = parsePreference(raw);
  const snapshot: VisibilitySnapshot =
    parsed === null ? NO_PREFERENCE : Object.freeze({ preference: parsed, storageReadable: true });
  snapshotCache.set(key, { raw, snapshot });
  return snapshot;
}

/**
 * The snapshot used while server-rendering and during hydration. Constant on
 * purpose: the server cannot see this browser's storage, so the first paint
 * is the role default and `useSyncExternalStore` swaps in the stored
 * preference once the client takes over.
 */
export function serverWidgetVisibility(): VisibilitySnapshot {
  return NO_PREFERENCE;
}

const listeners = new Set<() => void>();

function notifyListeners() {
  for (const listener of [...listeners]) listener();
}

/**
 * Subscribes to changes. The `storage` event only fires for *other* tabs, so
 * same-tab writes are announced through the local listener set.
 *
 * Stable module-level function: passing a fresh closure to
 * `useSyncExternalStore` would resubscribe on every render.
 */
export function subscribeWidgetVisibility(onChange: () => void): () => void {
  listeners.add(onChange);
  if (typeof window !== "undefined") window.addEventListener("storage", onChange);
  return () => {
    listeners.delete(onChange);
    if (typeof window !== "undefined") window.removeEventListener("storage", onChange);
  };
}

/**
 * Stores the full set of widgets this user has hidden. Returns false when
 * the write did not happen (no known user, or storage refused), so the
 * caller can say so rather than implying the choice was remembered.
 */
export function writeWidgetVisibility(userId: number | null, hidden: readonly WidgetId[]): boolean {
  if (typeof window === "undefined" || userId === null) return false;
  let stored = true;
  try {
    window.localStorage.setItem(widgetVisibilityStorageKey(userId), JSON.stringify({ hidden: [...hidden] }));
  } catch {
    stored = false;
  }
  notifyListeners();
  return stored;
}

/**
 * Drops this user's stored choices so the role default applies again.
 * Returns false when the removal did not happen.
 */
export function clearWidgetVisibility(userId: number | null): boolean {
  if (typeof window === "undefined" || userId === null) return false;
  let cleared = true;
  try {
    window.localStorage.removeItem(widgetVisibilityStorageKey(userId));
  } catch {
    cleared = false;
  }
  notifyListeners();
  return cleared;
}

/**
 * Resolves the widgets to hide, given what is actually in the layout.
 *
 * Precedence: the user's stored choices win; failing that the role default;
 * failing that nothing is hidden.
 *
 * The last clause is the guard that matters most -- a role default that
 * happens to share no widget with this user's layout would otherwise hide
 * every card and leave a blank page. A default is only applied when it
 * leaves something on screen; an explicit user choice to hide everything is
 * still honoured, because that is a decision they made and can undo.
 */
export function resolveHiddenWidgets(
  preference: VisibilityPreference | null,
  role: string | null | undefined,
  widgetsInLayout: readonly WidgetId[],
): Set<WidgetId> {
  const present = new Set(widgetsInLayout);
  if (preference) {
    return new Set(preference.hidden.filter((id) => present.has(id)));
  }
  const defaults = defaultWidgetsForRole(role);
  if (!defaults) return new Set<WidgetId>();
  const allowed = new Set(defaults);
  const hidden = new Set([...present].filter((id) => !allowed.has(id)));
  // A role guess must never be the reason the dashboard looks broken. The
  // user has not chosen anything yet at this point -- this is a first-run
  // default -- so if the profile would hide at least half the board, the
  // profile is wrong for this layout and showing everything is the safer
  // answer. Guessing a persona is worth a little tidying, never most of the
  // page.
  if (hidden.size * 2 >= present.size) return new Set<WidgetId>();
  return hidden;
}
