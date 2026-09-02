/**
 * Standard Library Type Primitives
 */

/**
 * Represents a value of type `T` that may also be `null` or `undefined`.
 *
 * @example
 * ```ts
 * type MaybeString = Nullable<string>; // string | null | undefined
 * ```
 */
export type Nullable<T> = T | null | undefined;

/**
 * Constructs a type consisting of `T` with `null` and `undefined` excluded.
 * Equivalent to TypeScript's built-in `NonNullable<T>`.
 *
 * @example
 * ```ts
 * type Clean = IsDefinedNotNull<string | null | undefined>; // string
 * ```
 */
export type IsDefinedNotNull<T> = NonNullable<T>;

/**
 * Represents an optional value of type `T` (may be `undefined`).
 *
 * @example
 * ```ts
 * type OptNumber = Optional<number>; // number | undefined
 * ```
 */
export type Optional<T> = T | undefined;

/**
 * Extracts the union of value types contained in object type `T`.
 *
 * @example
 * ```ts
 * const Severities = { HIGH: "high", LOW: "low" } as const;
 * type SeverityValue = ValueOf<typeof Severities>; // "high" | "low"
 * ```
 */
export type ValueOf<T> = T[keyof T];
