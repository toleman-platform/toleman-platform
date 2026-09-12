/**
 * Standard Library Error Handling & Normalization Utilities
 */

/**
 * Safely extracts an error message string from an unknown catch clause value.
 *
 * @param error The caught error value (Error, string, object, or unknown)
 * @param fallback Optional fallback message when error has no usable string representation
 * @returns A guaranteed non-empty error message string
 *
 * @example
 * ```ts
 * try {
 *   await saveData();
 * } catch (e) {
 *   setError(getErrorMessage(e, "Failed to save data"));
 * }
 * ```
 */
export function getErrorMessage(
  error: unknown,
  fallback = "Something went wrong",
): string {
  if (error instanceof Error) {
    return error.message || fallback;
  }
  if (typeof error === "string" && error.trim().length > 0) {
    return error;
  }
  if (
    error !== null &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message: unknown }).message === "string"
  ) {
    return (error as { message: string }).message || fallback;
  }
  return fallback;
}

/**
 * Normalizes any caught or thrown value into a standard JavaScript Error instance.
 *
 * @param thrown Any value thrown in a try/catch or promise rejection
 * @param fallback Optional fallback message when thrown has no representation
 * @returns A real Error instance
 *
 * @example
 * ```ts
 * const err = toError("Network request failed"); // Error("Network request failed")
 * ```
 */
export function toError(thrown: unknown, fallback = "Something went wrong"): Error {
  if (thrown instanceof Error) {
    return thrown;
  }
  if (typeof thrown === "string" && thrown.trim().length > 0) {
    return new Error(thrown);
  }
  return new Error(fallback);
}
