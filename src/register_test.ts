import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "./register.ts";
import { ECDSA_SHA_256, EDDSA, RSASSA_PKCS1_v1_5_SHA_256 } from "./deps.ts";
import { decodeBase64Url } from "./deps.ts";
import { timingSafeEqual } from "https://deno.land/std@0.160.0/crypto/timing_safe_equal.ts";
import { AuthenticatorAttestationResponse } from "./types.ts";

const ENCODER = new TextEncoder();

const CHALLENGE1 = decodeBase64Url(
  "NsBvZs-QCV7GmAlfXno4IIKdB-3ctuBLwzvF9yTg9-w",
);

const RSA_CHALLENGE = decodeBase64Url(
  "j9OlhTRaZkF5_CC7P3uTn8t1NGYF9ujB4gSe6dtSvEU_RnxZVSiQs_k9nkmfzcgfAAABipBCpa6oR_D0VCCeN1JxzN0",
);

const ECDSA_CHALLENGE = decodeBase64Url(
  "LtqCES8H7iaIfqUHNDBOx3IRKLmhxze2QiO5b0KfsizByCBhY7ppivunLKEYKDDZAAABipCuvAqTFWLdAsycMgDAFEs",
);

describe("Registration", () => {
  it("Can generate registration options", async () => {
    const options = await generateRegistrationOptions({
      rpName: "levischuck",
      rpId: "levischuck.com",
      userDisplayName: "Toucan",
      userId: ENCODER.encode("Taco"), // I was feeling for tacos at that moment
      userName: "Taco",
      supportedAlgorithms: [EDDSA, ECDSA_SHA_256, RSASSA_PKCS1_v1_5_SHA_256],
      challenge: CHALLENGE1,
    });
    assertEquals(options.rp, { name: "levischuck", id: "levischuck.com" });
    assertEquals(options.pubKeyCredParams, [
      { type: "public-key", alg: EDDSA },
      { type: "public-key", alg: ECDSA_SHA_256 },
      { type: "public-key", alg: RSASSA_PKCS1_v1_5_SHA_256 },
    ]);
    assert(timingSafeEqual(options.challenge, CHALLENGE1));
    assertEquals(options.user, {
      displayName: "Toucan",
      id: ENCODER.encode("Taco"),
      name: "Taco",
    });
  });
  it("Can verify an Ed25519 registration", async () => {
    const credential = {
      rawId: decodeBase64Url("OUf0LGAmowUoH8OnTklJAQ"),
      id: "OUf0LGAmowUoH8OnTklJAQ",
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTnNCdlpzLVFDVjdHbUFsZlhubzRJSUtkQi0zY3R1Qkx3enZGOXlUZzktdyIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        ),
        attestationObject: decodeBase64Url(
          "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVh_GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgnFAAAAAQAAAAAAAAAAAAAAAAAAAAAAEDlH9CxgJqMFKB_Dp05JSQGkAQEDJyAGIVggcBgGHdrhFKK69xI3rUwgvNY3fI9Nscgmgx4YNeqor8uha2NyZWRQcm90ZWN0Ag",
        ),
      } as AuthenticatorAttestationResponse,
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: CHALLENGE1,
      expectedAlgorithms: [EDDSA],
      origin: "https://levischuck.com",
      rpId: "levischuck.com",
    });
    assertEquals(
      verified.attestationObject,
      credential.response.attestationObject,
    );
    assertEquals(verified.clientDataJSON, credential.response.clientDataJSON);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
    assertEquals(verified.credentialId, credential.rawId);
    assertEquals(verified.signCount, 1);
    assertEquals(
      verified.coseKey,
      decodeBase64Url(
        "pAEBAycgBiFYIHAYBh3a4RSiuvcSN61MILzWN3yPTbHIJoMeGDXqqK_L",
      ),
    );
  });
  it("Can verify an RS256 registration", async () => {
    const credential = {
      rawId: decodeBase64Url("aZfhRcejIPt0GtBAYbBC3SphTx_eegh5S-UX4I6DmmE"),
      id: "aZfhRcejIPt0GtBAYbBC3SphTx_eegh5S-UX4I6DmmE",
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiajlPbGhUUmFaa0Y1X0NDN1AzdVRuOHQxTkdZRjl1akI0Z1NlNmR0U3ZFVV9SbnhaVlNpUXNfazlua21memNnZkFBQUJpcEJDcGE2b1JfRDBWQ0NlTjFKeHpOMCIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXMtbWFjYm9vay1wcm8ubG9jYWw6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        ),
        attestationObject: decodeBase64Url(
          "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ7po2_gzuGLPA_PQd9-sekRt6_C7l4Qtb0QQBXAKCoTYRQAAAAAAAAAAAAAAAAAAAAAAAAAAACBpl-FFx6Mg-3Qa0EBhsELdKmFPH956CHlL5RfgjoOaYaQBAwM5AQAgWQEAmsNFll9haOt01PH8RVQoipMhe9m0xXM_MPSPGoq8QYrn9yuDjOw4qVnx5B8ScuML4hlw6xfvuyN-FhZ9IEAWFmbLCafLks7-LXkdFu35YbP1TGbkepAVRp3H-aRYfLA9Dt6hxeJ6Z3G83m7asjGk4Vw62LNRa6aprGJ7N90hL7bsMHNOflYpTKNaTRSaqqlydm_L1jXns5yb0-86GnvrXTMlBD2wnbrODdaxzidHFf0KhNP_yPAJDe5Tt9jVez9-mRRxMNAm0Lonivlvv1RshubvKVCxKQfnd_CVoEP04-2ZT0uG7J7aE4t0ucxqf6hJxbWQ_WCd3Inh1Z8GY1r6tyFDAQAB",
        ),
      } as AuthenticatorAttestationResponse,
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: RSA_CHALLENGE,
      expectedAlgorithms: [RSASSA_PKCS1_v1_5_SHA_256],
      origin: "https://levis-macbook-pro.local:8443",
      rpId: "levis-macbook-pro.local",
    });
    assertEquals(
      verified.attestationObject,
      credential.response.attestationObject,
    );
    assertEquals(verified.clientDataJSON, credential.response.clientDataJSON);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
    assertEquals(verified.credentialId, credential.rawId);
    assertEquals(verified.signCount, 0);
    assertEquals(
      verified.coseKey,
      decodeBase64Url(
        "pAEDAzkBACBZAQCaw0WWX2Fo63TU8fxFVCiKkyF72bTFcz8w9I8airxBiuf3K4OM7DipWfHkHxJy4wviGXDrF--7I34WFn0gQBYWZssJp8uSzv4teR0W7flhs_VMZuR6kBVGncf5pFh8sD0O3qHF4npncbzebtqyMaThXDrYs1FrpqmsYns33SEvtuwwc05-VilMo1pNFJqqqXJ2b8vWNeeznJvT7zoae-tdMyUEPbCdus4N1rHOJ0cV_QqE0__I8AkN7lO32NV7P36ZFHEw0CbQuieK-W-_VGyG5u8pULEpB-d38JWgQ_Tj7ZlPS4bsntoTi3S5zGp_qEnFtZD9YJ3cieHVnwZjWvq3IUMBAAE",
      ),
    );
  });
  it("Can verify an ES256 registration", async () => {
    const credential = {
      rawId: decodeBase64Url(
        "YOgmRpF5PncY0hQtSVEKAqH93RWUHKm_Tq3qJJ3dIyB0qwhBMA34LxbgnaIyZQMWV1J6keFXlYLX6lPtsD0kOQ",
      ),
      id:
        "YOgmRpF5PncY0hQtSVEKAqH93RWUHKm_Tq3qJJ3dIyB0qwhBMA34LxbgnaIyZQMWV1J6keFXlYLX6lPtsD0kOQ",
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response: {
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTHRxQ0VTOEg3aWFJZnFVSE5EQk94M0lSS0xtaHh6ZTJRaU81YjBLZnNpekJ5Q0JoWTdwcGl2dW5MS0VZS0REWkFBQUJpcEN1dkFxVEZXTGRBc3ljTWdEQUZFcyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        ),
        attestationObject: decodeBase64Url(
          "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQAAAAAAAAAAAAAAAAAAAAAAQGDoJkaReT53GNIULUlRCgKh_d0VlBypv06t6iSd3SMgdKsIQTAN-C8W4J2iMmUDFldSepHhV5WC1-pT7bA9JDmlAQIDJiABIVgg4eN_jI9illg8tP7AifxoOvLa210adyfdl0bPa3bITukiWCBe8he-x7LF68x9aduIAfurpro_4VMzki7r_LVIjfdE-A",
        ),
      } as AuthenticatorAttestationResponse,
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: ECDSA_CHALLENGE,
      expectedAlgorithms: [ECDSA_SHA_256],
      origin: "https://localhost:8443",
      rpId: "localhost",
    });
    assertEquals(
      verified.attestationObject,
      credential.response.attestationObject,
    );
    assertEquals(verified.clientDataJSON, credential.response.clientDataJSON);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
    assertEquals(verified.credentialId, credential.rawId);
    assertEquals(verified.signCount, 1);
    assertEquals(
      verified.coseKey,
      decodeBase64Url(
        "pQECAyYgASFYIOHjf4yPYpZYPLT-wIn8aDry2ttdGncn3ZdGz2t2yE7pIlggXvIXvseyxevMfWnbiAH7q6a6P-FTM5Iu6_y1SI33RPg",
      ),
    );
  });
});
