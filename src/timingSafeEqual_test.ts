import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { timingSafeEqual } from "./timingSafeEqual.ts";

describe("timingSafeEqual", () => {
  it("compares matching and different Uint8Array values", () => {
    assert(timingSafeEqual(
      new Uint8Array([1, 2, 3]),
      new Uint8Array([1, 2, 3]),
    ));
    assertFalse(timingSafeEqual(
      new Uint8Array([1, 2, 3]),
      new Uint8Array([1, 2, 4]),
    ));
  });

  it("rejects values with different lengths", () => {
    assertFalse(timingSafeEqual(
      new Uint8Array([1, 2, 3]),
      new Uint8Array([1, 2]),
    ));
  });

  it("compares ArrayBuffer and DataView inputs", () => {
    const a = new Uint8Array([9, 8, 7]).buffer;
    const b = new Uint8Array([9, 8, 7]).buffer;
    const c = new DataView(new Uint8Array([9, 8, 6]).buffer);

    assert(timingSafeEqual(a, b));
    assertFalse(timingSafeEqual(new DataView(a), c));
    assertEquals(timingSafeEqual(new DataView(a), new DataView(b)), true);
  });
});
