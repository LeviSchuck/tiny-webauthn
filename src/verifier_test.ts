import { assertEquals, assertFalse, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { decodeBase64Url, ECDSA_SHA_256, ECDSA_SHA_384 } from "./deps.ts";
import { unwrapAsn1EC2Signature, verifySignature } from "./verifier.ts";

function ecdsaSignature(r: Uint8Array, s: Uint8Array): Uint8Array {
  const contents = new Uint8Array(2 + r.length + 2 + s.length);
  contents.set([0x02, r.length], 0);
  contents.set(r, 2);
  contents.set([0x02, s.length], 2 + r.length);
  contents.set(s, 4 + r.length);

  const signature = new Uint8Array(2 + contents.length);
  signature.set([0x30, contents.length], 0);
  signature.set(contents, 2);
  return signature;
}

describe("Unwrap EC2 Signature", () => {
  it("Unwraps as expected with no padding", () => {
    const signature = decodeBase64Url(
      "MEQCIH2YqUyLH935kIoZb94Qzh58U3DT2wNiGl-ddQyuMOzdAiBbNR9RB9f2Lg7_645X8urPkGJ1Tu7AtzihXg-CAP0pKQ",
    );
    // const expected_r = decodeHex('7D98A94C8B1FDDF9908A196FDE10CE1E7C5370D3DB03621A5F9D750CAE30ECDD');
    // const expected_s = decodeHex('5B351F5107D7F62E0EFFEB8E57F2EACF9062754EEEC0B738A15E0F8200FD2929');
    const expected = decodeBase64Url(
      "fZipTIsf3fmQihlv3hDOHnxTcNPbA2IaX511DK4w7N1bNR9RB9f2Lg7_645X8urPkGJ1Tu7AtzihXg-CAP0pKQ",
    );
    assertEquals(unwrapAsn1EC2Signature(signature, ECDSA_SHA_256), expected);
  });
  it("Unwraps as expected with 0 padding", () => {
    const signature = decodeBase64Url(
      "MEYCIQCrvseRAs34FhEOYo9Cl2nuT9vyDVHlxWR7OjPESNcljQIhAP7KY1XT8ZUe5WubBKi9wK8In9s0wpw_pHNPkKdU_oUL",
    );
    // const expected_r = decodeHex('ABBEC79102CDF816110E628F429769EE4FDBF20D51E5C5647B3A33C448D7258D');
    // const expected_s = decodeHex('FECA6355D3F1951EE56B9B04A8BDC0AF089FDB34C29C3FA4734F90A754FE850B');
    const expected = decodeBase64Url(
      "q77HkQLN-BYRDmKPQpdp7k_b8g1R5cVkezozxEjXJY3-ymNV0_GVHuVrmwSovcCvCJ_bNMKcP6RzT5CnVP6FCw",
    );
    assertEquals(unwrapAsn1EC2Signature(signature, ECDSA_SHA_256), expected);
  });

  it("unwraps signatures using one-byte and two-byte long-form lengths", () => {
    const expected = new Uint8Array(64);
    const contents = ecdsaSignature(new Uint8Array(32), new Uint8Array(32))
      .slice(2);

    const oneByteLength = new Uint8Array(3 + contents.length);
    oneByteLength.set([0x30, 0x81, contents.length], 0);
    oneByteLength.set(contents, 3);
    assertEquals(
      unwrapAsn1EC2Signature(oneByteLength, ECDSA_SHA_256),
      expected,
    );

    const twoByteLength = new Uint8Array(4 + contents.length);
    twoByteLength.set([0x30, 0x82, 0x00, contents.length], 0);
    twoByteLength.set(contents, 4);
    assertEquals(
      unwrapAsn1EC2Signature(twoByteLength, ECDSA_SHA_256),
      expected,
    );
  });

  it("rejects unsupported and malformed ASN.1 signatures", () => {
    assertThrows(
      () =>
        unwrapAsn1EC2Signature(
          ecdsaSignature(new Uint8Array(32), new Uint8Array(32)),
          ECDSA_SHA_384,
        ),
      Error,
      "Unsupported algorithm",
    );
    assertThrows(
      () => unwrapAsn1EC2Signature(new Uint8Array([0x31, 0]), ECDSA_SHA_256),
      Error,
      "Signature is not asn.1",
    );
    assertThrows(
      () =>
        unwrapAsn1EC2Signature(
          new Uint8Array([0x30, 0x83, 0, 0, 0]),
          ECDSA_SHA_256,
        ),
      Error,
      "Unexpected asn.1 length",
    );
    assertThrows(
      () => unwrapAsn1EC2Signature(new Uint8Array([0x30, 0x80]), ECDSA_SHA_256),
      Error,
      "Indefinite lengths are not supported",
    );
    assertThrows(
      () =>
        unwrapAsn1EC2Signature(new Uint8Array([0x30, 2, 0x02]), ECDSA_SHA_256),
      Error,
      "Corrupted asn.1",
    );
    assertThrows(
      () => {
        const signature = ecdsaSignature(
          new Uint8Array(32),
          new Uint8Array(32),
        );
        signature[2] = 0x03;
        unwrapAsn1EC2Signature(signature, ECDSA_SHA_256);
      },
      Error,
      "Signature is not asn.1",
    );
    assertThrows(
      () => {
        const signature = ecdsaSignature(
          new Uint8Array(32),
          new Uint8Array(32),
        );
        signature[36] = 0x03;
        unwrapAsn1EC2Signature(signature, ECDSA_SHA_256);
      },
      Error,
      "Signature is not asn.1",
    );
  });

  it("rejects overlong signature components without leading padding", () => {
    assertThrows(
      () =>
        unwrapAsn1EC2Signature(
          ecdsaSignature(new Uint8Array(33).fill(1), new Uint8Array(32)),
          ECDSA_SHA_256,
        ),
      Error,
      "r component is too long",
    );
    assertThrows(
      () =>
        unwrapAsn1EC2Signature(
          ecdsaSignature(new Uint8Array(32), new Uint8Array(33).fill(1)),
          ECDSA_SHA_256,
        ),
      Error,
      "s component is too long",
    );
  });

  it("returns false for unsupported signature algorithms", async () => {
    const { publicKey } = await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    ) as CryptoKeyPair;

    assertFalse(
      await verifySignature(
        -999 as never,
        publicKey,
        new Uint8Array(),
        new Uint8Array(),
      ),
    );
  });
});
