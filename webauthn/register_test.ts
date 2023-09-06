import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import { generateRegistrationOptions, verifyRegistrationResponse } from "./register.ts";
import { ECDSA_SHA_256, EDDSA, RSASSA_PKCS1_v1_5_SHA_256 } from "./deps.ts";
import { decodeBase64Url } from "./deps.ts";
import { timingSafeEqual } from "https://deno.land/std@0.160.0/crypto/timing_safe_equal.ts";
import { AuthenticatorAttestationResponse } from "./types.ts";

const ENCODER = new TextEncoder();

const CHALLENGE1 = decodeBase64Url("NsBvZs-QCV7GmAlfXno4IIKdB-3ctuBLwzvF9yTg9-w");

describe("Registration", () => {
  it("Can generate registration options", async () => {
    const options = await generateRegistrationOptions({
      rpName: "levischuck",
      rpId: "levischuck.com",
      userDisplayName: "Toucan",
      userId: ENCODER.encode("Taco"), // I was feeling for tacos at that moment
      userName: "Taco",
      supportedAlgorithms: [EDDSA, ECDSA_SHA_256, RSASSA_PKCS1_v1_5_SHA_256],
      challenge: CHALLENGE1
    });
    assertEquals(options.rp, {name: "levischuck", id: "levischuck.com"});
    assertEquals(options.pubKeyCredParams, [
      {type: "public-key", alg: EDDSA},
      {type: "public-key", alg: ECDSA_SHA_256},
      {type: "public-key", alg: RSASSA_PKCS1_v1_5_SHA_256}
    ]);
    assert(timingSafeEqual(options.challenge, CHALLENGE1));
    assertEquals(options.user, {displayName: "Toucan", id: ENCODER.encode("Taco"), name: "Taco"});
  });
  it("Can verify a registration", async () => {
    const credential = {
      rawId: decodeBase64Url("OUf0LGAmowUoH8OnTklJAQ"),
      id: "OUf0LGAmowUoH8OnTklJAQ",
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: decodeBase64Url(
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTnNCdlpzLVFDVjdHbUFsZlhubzRJSUtkQi0zY3R1Qkx3enZGOXlUZzktdyIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
        ),
        attestationObject: decodeBase64Url(
          'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVh_GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgnFAAAAAQAAAAAAAAAAAAAAAAAAAAAAEDlH9CxgJqMFKB_Dp05JSQGkAQEDJyAGIVggcBgGHdrhFKK69xI3rUwgvNY3fI9Nscgmgx4YNeqor8uha2NyZWRQcm90ZWN0Ag'
        ),
      } as AuthenticatorAttestationResponse
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: CHALLENGE1,
      expectedAlgorithms: [EDDSA, ECDSA_SHA_256, RSASSA_PKCS1_v1_5_SHA_256],
      origin: "https://levischuck.com",
      rpId: "levischuck.com",
    });
    assertEquals(verified.attestationObject, credential.response.attestationObject);
    assertEquals(verified.clientDataJSON, credential.response.clientDataJSON);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
    assertEquals(verified.credentialId, credential.rawId);
    assertEquals(verified.signCount, 1);
    assertEquals(verified.coseKey, decodeBase64Url('pAEBAycgBiFYIHAYBh3a4RSiuvcSN61MILzWN3yPTbHIJoMeGDXqqK_L'));
  })
});