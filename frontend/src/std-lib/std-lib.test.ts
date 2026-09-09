import { describe, it, expect, expectTypeOf } from "vitest";
import {
  type Nullable,
  type IsDefinedNotNull,
  type Optional,
  type ValueOf,
  isDefinedNotNull,
  isNullable,
  isNonEmptyArray,
  clamp,
  formatPercent,
  roundTo,
  getErrorMessage,
  toError,
  sleep,
  settleOrNull,
  unique,
  uniqueBy,
  paginateSlice,
  truncate,
  capitalize,
} from "./index";

describe("std-lib type primitives", () => {
  it("verifies Nullable<T> allows T and null", () => {
    type TestType = Nullable<string>;

    expectTypeOf<TestType>().toEqualTypeOf<string | null>();

    const a: TestType = "hello";
    const b: TestType = null;

    expect(a).toBe("hello");
    expect(b).toBeNull();
  });

  it("verifies IsDefinedNotNull<T> excludes both null and undefined", () => {
    type Source = string | null | undefined;
    type Stripped = IsDefinedNotNull<Source>;

    expectTypeOf<Stripped>().toEqualTypeOf<string>();

    const val: Stripped = "clean";
    expect(val).toBe("clean");
  });

  it("verifies Optional<T> allows T and undefined", () => {
    type TestOpt = Optional<number>;
    expectTypeOf<TestOpt>().toEqualTypeOf<number | undefined>();

    const x: TestOpt = 42;
    const y: TestOpt = undefined;
    expect(x).toBe(42);
    expect(y).toBeUndefined();
  });

  it("verifies ValueOf<T> extracts object property value union", () => {
    const Statuses = {
      ACTIVE: "active",
      INACTIVE: "inactive",
      PENDING: "pending",
    } as const;

    type StatusValue = ValueOf<typeof Statuses>;
    expectTypeOf<StatusValue>().toEqualTypeOf<"active" | "inactive" | "pending">();
    expect(Statuses.ACTIVE).toBe("active");
  });
});

describe("isDefinedNotNull", () => {
  it("returns false for null and undefined", () => {
    expect(isDefinedNotNull(null)).toBe(false);
    expect(isDefinedNotNull(undefined)).toBe(false);
  });

  it("returns true for falsy non-null values", () => {
    expect(isDefinedNotNull(0)).toBe(true);
    expect(isDefinedNotNull("")).toBe(true);
    expect(isDefinedNotNull(false)).toBe(true);
    expect(isDefinedNotNull(NaN)).toBe(true);
  });

  it("returns true for truthy values", () => {
    expect(isDefinedNotNull("hello")).toBe(true);
    expect(isDefinedNotNull(123)).toBe(true);
    expect(isDefinedNotNull({})).toBe(true);
    expect(isDefinedNotNull([])).toBe(true);
  });

  it("narrows array element types when filtering", () => {
    const raw: (string | number | null | undefined)[] = [
      "alpha",
      null,
      42,
      undefined,
      "beta",
    ];

    const clean = raw.filter(isDefinedNotNull);
    expectTypeOf(clean).toEqualTypeOf<(string | number)[]>();
    expect(clean).toEqual(["alpha", 42, "beta"]);
  });
});

describe("isNullable", () => {
  it("returns true for null and undefined", () => {
    expect(isNullable(null)).toBe(true);
    expect(isNullable(undefined)).toBe(true);
  });

  it("returns false for defined values", () => {
    expect(isNullable(0)).toBe(false);
    expect(isNullable("")).toBe(false);
    expect(isNullable(false)).toBe(false);
    expect(isNullable("value")).toBe(false);
    expect(isNullable({})).toBe(false);
  });
});

describe("isNonEmptyArray", () => {
  it("returns true for populated arrays", () => {
    expect(isNonEmptyArray([1])).toBe(true);
    expect(isNonEmptyArray(["a", "b"])).toBe(true);
  });

  it("returns false for empty arrays, null, or undefined", () => {
    expect(isNonEmptyArray([])).toBe(false);
    expect(isNonEmptyArray(null)).toBe(false);
    expect(isNonEmptyArray(undefined)).toBe(false);
  });

  it("correctly narrows the type to a non-empty tuple", () => {
    const list: string[] = ["item1", "item2"];
    if (isNonEmptyArray(list)) {
      expectTypeOf(list).toEqualTypeOf<[string, ...string[]]>();
      const first: string = list[0];
      expect(first).toBe("item1");
    }
  });
});

describe("clamp", () => {
  it("clamps values exceeding bounds", () => {
    expect(clamp(150, 0, 100)).toBe(100);
    expect(clamp(-50, 0, 100)).toBe(0);
  });

  it("leaves values within bounds unchanged", () => {
    expect(clamp(50, 0, 100)).toBe(50);
    expect(clamp(0, 0, 100)).toBe(0);
    expect(clamp(100, 0, 100)).toBe(100);
  });

  it("throws when min > max", () => {
    expect(() => clamp(10, 100, 0)).toThrow(RangeError);
  });
});

describe("formatPercent", () => {
  it("formats decimal ratios to percentages without decimals", () => {
    expect(formatPercent(0.854)).toBe("85%");
    expect(formatPercent(1)).toBe("100%");
    expect(formatPercent(0)).toBe("0%");
  });

  it("formats decimal ratios with specified decimal places", () => {
    expect(formatPercent(0.8546, 1)).toBe("85.5%");
    expect(formatPercent(0.8546, 2)).toBe("85.46%");
  });
});

describe("roundTo", () => {
  it("rounds to specified decimal places", () => {
    expect(roundTo(3.14159, 2)).toBe(3.14);
    expect(roundTo(3.14159, 3)).toBe(3.142);
    expect(roundTo(3.14159, 0)).toBe(3);
  });
});

describe("getErrorMessage", () => {
  it("extracts message from Error instances", () => {
    expect(getErrorMessage(new Error("Connection timeout"))).toBe("Connection timeout");
  });

  it("returns raw string if error is a string", () => {
    expect(getErrorMessage("Custom error string")).toBe("Custom error string");
  });

  it("extracts message property from error-like objects", () => {
    expect(getErrorMessage({ message: "Object error message" })).toBe("Object error message");
  });

  it("falls back to default fallback for unknown types", () => {
    expect(getErrorMessage(null)).toBe("Something went wrong");
    expect(getErrorMessage(undefined)).toBe("Something went wrong");
    expect(getErrorMessage(12345, "Custom fallback")).toBe("Custom fallback");
  });
});

describe("toError", () => {
  it("returns existing Error instances as-is", () => {
    const original = new Error("Sample error");
    expect(toError(original)).toBe(original);
  });

  it("wraps strings into new Error instances", () => {
    const converted = toError("Network failure");
    expect(converted).toBeInstanceOf(Error);
    expect(converted.message).toBe("Network failure");
  });

  it("falls back to default Error for unhandled values", () => {
    const err = toError(null);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe("Something went wrong");
  });
});

describe("async utilities", () => {
  it("sleep pauses for given duration", async () => {
    const start = Date.now();
    await sleep(20);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(15);
  });

  it("settleOrNull returns resolved value on success", async () => {
    const res = await settleOrNull(Promise.resolve("data"));
    expect(res).toBe("data");
  });

  it("settleOrNull returns null on rejection", async () => {
    const res = await settleOrNull(Promise.reject(new Error("Failed")));
    expect(res).toBeNull();
  });
});

describe("array utilities", () => {
  it("unique removes duplicates while preserving order", () => {
    expect(unique([1, 2, 2, 3, 1, 4])).toEqual([1, 2, 3, 4]);
    expect(unique(["a", "b", "a", "c"])).toEqual(["a", "b", "c"]);
    expect(unique([])).toEqual([]);
  });

  it("uniqueBy removes items by unique key selector", () => {
    const items = [
      { id: 1, name: "Alpha" },
      { id: 2, name: "Beta" },
      { id: 1, name: "Alpha Duplicate" },
    ];
    const deduped = uniqueBy(items, (item) => item.id);
    expect(deduped).toEqual([
      { id: 1, name: "Alpha" },
      { id: 2, name: "Beta" },
    ]);
  });

  it("paginateSlice slices items and clamps page accurately", () => {
    const list = Array.from({ length: 55 }, (_, i) => i + 1);

    // Page 1
    const p1 = paginateSlice(list, 1, 20);
    expect(p1.clampedPage).toBe(1);
    expect(p1.totalPages).toBe(3);
    expect(p1.totalItems).toBe(55);
    expect(p1.items).toHaveLength(20);
    expect(p1.items[0]).toBe(1);

    // Out of bounds page (clamped to max)
    const pOverflow = paginateSlice(list, 999, 20);
    expect(pOverflow.clampedPage).toBe(3);
    expect(pOverflow.items).toHaveLength(15);
    expect(pOverflow.items[14]).toBe(55);

    // Below bounds page (clamped to min)
    const pUnderflow = paginateSlice(list, 0, 20);
    expect(pUnderflow.clampedPage).toBe(1);
    expect(pUnderflow.items).toHaveLength(20);

    // Empty list
    const pEmpty = paginateSlice([], 1, 20);
    expect(pEmpty.clampedPage).toBe(1);
    expect(pEmpty.totalPages).toBe(1);
    expect(pEmpty.items).toEqual([]);
  });
});

describe("string utilities", () => {
  it("truncate trims long strings and appends ellipsis", () => {
    expect(truncate("Hello, World!", 5)).toBe("Hello…");
    expect(truncate("Short", 10)).toBe("Short");
    expect(truncate("Custom", 4, "...")).toBe("Cust...");
  });

  it("capitalize makes the first letter uppercase", () => {
    expect(capitalize("hello")).toBe("Hello");
    expect(capitalize("alreadyCapital")).toBe("AlreadyCapital");
    expect(capitalize("")).toBe("");
  });
});
