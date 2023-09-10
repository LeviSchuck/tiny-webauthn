import { assertEquals } from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import { decodeBase64Url, ECDSA_SHA_256 } from "./deps.ts";
import { unwrapAsn1EC2Signature } from "./verifier.ts";

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
});
