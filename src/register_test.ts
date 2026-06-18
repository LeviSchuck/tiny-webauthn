import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";
import { describe, it } from "@std/testing/bdd";
import {
  generateRegistrationOptions,
  parseCreateResponse,
  type RegistrationVerification,
  verifyRegistrationResponse,
} from "./register.ts";
import {
  decodeBase64Url,
  ECDSA_SHA_256,
  EDDSA,
  encodeBase64Url,
  RSASSA_PKCS1_v1_5_SHA_256,
} from "./deps.ts";
import type { AuthenticatorAttestationResponse } from "./types.ts";

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

function ed25519AttestationResponse(): AuthenticatorAttestationResponse {
  return {
    clientDataJSON: decodeBase64Url(
      "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTnNCdlpzLVFDVjdHbUFsZlhubzRJSUtkQi0zY3R1Qkx3enZGOXlUZzktdyIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
    ),
    attestationObject: decodeBase64Url(
      "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVh_GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgnFAAAAAQAAAAAAAAAAAAAAAAAAAAAAEDlH9CxgJqMFKB_Dp05JSQGkAQEDJyAGIVggcBgGHdrhFKK69xI3rUwgvNY3fI9Nscgmgx4YNeqor8uha2NyZWRQcm90ZWN0Ag",
    ),
  };
}

function clientData(overrides: Record<string, unknown>): Uint8Array {
  return ENCODER.encode(JSON.stringify({
    type: "webauthn.create",
    challenge: encodeBase64Url(CHALLENGE1),
    origin: "https://levischuck.com",
    crossOrigin: false,
    ...overrides,
  }));
}

function cborText(value: string): number[] {
  return [0x60 + value.length, ...ENCODER.encode(value)];
}

function cborBytes(value: Uint8Array): number[] {
  if (value.length < 24) {
    return [0x40 + value.length, ...value];
  }
  if (value.length <= 0xff) {
    return [0x58, value.length, ...value];
  }
  return [0x59, value.length >> 8, value.length & 0xff, ...value];
}

function attestationObject(
  fmt: string,
  attStmt: number[],
  authData: Uint8Array,
): Uint8Array {
  return new Uint8Array([
    0xa3,
    ...cborText("fmt"),
    ...cborText(fmt),
    ...cborText("attStmt"),
    ...attStmt,
    ...cborText("authData"),
    ...cborBytes(authData),
  ]);
}

function withCredentialId(
  authData: Uint8Array,
  credentialId: Uint8Array,
): Uint8Array {
  const credentialIdOffset = 55;
  const publicKeyOffset = credentialIdOffset + authData[54];
  const publicKey = authData.slice(publicKeyOffset);
  const next = new Uint8Array(
    credentialIdOffset + credentialId.length + publicKey.length,
  );
  next.set(authData.slice(0, credentialIdOffset), 0);
  next[53] = credentialId.length >> 8;
  next[54] = credentialId.length & 0xff;
  next.set(credentialId, credentialIdOffset);
  next.set(publicKey, credentialIdOffset + credentialId.length);
  return next;
}

function registrationVerification(
  response: AuthenticatorAttestationResponse = ed25519AttestationResponse(),
): RegistrationVerification {
  return {
    attestationResponse: response,
    challenge: CHALLENGE1,
    expectedAlgorithms: [EDDSA],
    origins: ["https://levischuck.com"],
    rpId: "levischuck.com",
  };
}

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

  it("Can generate registration options with optional fields", async () => {
    const excludeCredential = {
      type: "public-key" as const,
      id: decodeBase64Url("OUf0LGAmowUoH8OnTklJAQ"),
    };
    const passkeyOptions = await generateRegistrationOptions({
      rpName: "levischuck",
      userDisplayName: "Toucan",
      userId: ENCODER.encode("Taco"),
      userName: "Taco",
      challenge: CHALLENGE1,
      extensions: { appidExclude: "https://levischuck.com" },
      excludeCredentials: [excludeCredential],
      timeoutMilliseconds: 1200,
      userVerification: true,
      kind: "passkey",
    });

    assertEquals(
      passkeyOptions.authenticatorSelection?.residentKey,
      "required",
    );
    assertEquals(
      passkeyOptions.authenticatorSelection?.requireResidentKey,
      true,
    );
    assertEquals(
      passkeyOptions.authenticatorSelection?.userVerification,
      "required",
    );
    assertEquals(passkeyOptions.extensions, {
      appidExclude: "https://levischuck.com",
      credProps: true,
    });
    assertEquals(passkeyOptions.excludeCredentials, [excludeCredential]);
    assertEquals(passkeyOptions.timeout, 1200);

    const serverSideOptions = await generateRegistrationOptions({
      rpName: "levischuck",
      userDisplayName: "Toucan",
      userId: ENCODER.encode("Taco"),
      userName: "Taco",
      challenge: CHALLENGE1,
      userVerification: false,
      kind: "server-side",
    });
    assertEquals(
      serverSideOptions.authenticatorSelection?.residentKey,
      "discouraged",
    );
    assertEquals(
      serverSideOptions.authenticatorSelection?.userVerification,
      "discouraged",
    );

    const passkeyWithoutExtensions = await generateRegistrationOptions({
      rpName: "levischuck",
      userDisplayName: "Toucan",
      userId: ENCODER.encode("Taco"),
      userName: "Taco",
      challenge: CHALLENGE1,
      kind: "passkey",
    });
    assertEquals(passkeyWithoutExtensions.extensions, { credProps: true });
  });

  it("Rejects short registration challenges", async () => {
    await assertRejects(
      () =>
        generateRegistrationOptions({
          rpName: "levischuck",
          userDisplayName: "Toucan",
          userId: ENCODER.encode("Taco"),
          userName: "Taco",
          challenge: new Uint8Array(15),
        }),
      Error,
      "Insufficient challenge size",
    );
  });

  it("Rejects malformed create responses", () => {
    assertThrows(
      () => parseCreateResponse(new Uint8Array([0xf6])),
      Error,
      "Malformed create response",
    );
    assertThrows(
      () => parseCreateResponse(new Uint8Array([0xa0])),
      Error,
      "Malformed create response",
    );
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
      } satisfies AuthenticatorAttestationResponse,
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: CHALLENGE1,
      expectedAlgorithms: [EDDSA],
      origins: ["https://levischuck.com"],
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
      } satisfies AuthenticatorAttestationResponse,
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: RSA_CHALLENGE,
      expectedAlgorithms: [RSASSA_PKCS1_v1_5_SHA_256],
      origins: ["https://levis-macbook-pro.local:8443"],
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
      } satisfies AuthenticatorAttestationResponse,
    };
    const verified = await verifyRegistrationResponse({
      attestationResponse: credential.response,
      challenge: ECDSA_CHALLENGE,
      expectedAlgorithms: [ECDSA_SHA_256],
      origins: ["https://localhost:8443"],
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

  it("Rejects malformed registration client data", async () => {
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          clientDataJSON: new Uint8Array(),
        })),
      Error,
      "clientDataJSON must be provided",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          clientDataJSON: clientData({ type: "webauthn.get" }),
        })),
      Error,
      'Expected type to be "webauthn.create"',
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          clientDataJSON: clientData({ challenge: "" }),
        })),
      Error,
      "Challenge does not match",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse({
          ...registrationVerification(),
          origins: [],
        }),
      Error,
      "Expected an origin",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse({
          ...registrationVerification(),
          origins: ["https://example.com"],
        }),
      Error,
      "Expected origin",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          clientDataJSON: clientData({ topOrigin: "https://top.example" }),
        })),
      Error,
      "Unexpected topOrigin",
    );
  });

  it("Rejects malformed registration attestation data", async () => {
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: new Uint8Array([0xf6]),
        })),
      Error,
      "Malformed create response",
    );

    const authDataWithoutCredential = new Uint8Array(37);
    authDataWithoutCredential[32] = 0x01;
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xa0],
            authDataWithoutCredential,
          ),
        })),
      Error,
      "No authenticator data found",
    );

    await assertRejects(
      () =>
        verifyRegistrationResponse({
          ...registrationVerification(),
          rpId: "example.com",
        }),
      Error,
      "Relying Party ID mismatch",
    );
    const parsed = parseCreateResponse(
      ed25519AttestationResponse().attestationObject,
    );
    const authDataWithoutUserPresence = new Uint8Array(parsed.authDataBytes);
    authDataWithoutUserPresence[32] = 0x44;
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xa0],
            authDataWithoutUserPresence,
          ),
        })),
      Error,
      "Expected user presence",
    );

    const authDataWithoutUserVerification = new Uint8Array(
      parsed.authDataBytes,
    );
    authDataWithoutUserVerification[32] = 0x41;
    await assertRejects(
      () =>
        verifyRegistrationResponse({
          ...registrationVerification(),
          expectUserVerification: true,
          attestationResponse: {
            ...ed25519AttestationResponse(),
            attestationObject: attestationObject(
              "none",
              [0xa0],
              authDataWithoutUserVerification,
            ),
          },
        }),
      Error,
      "Expected user verified",
    );
    const backupStateWithoutEligibility = new Uint8Array(parsed.authDataBytes);
    backupStateWithoutEligibility[32] = 0x51;
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xa0],
            backupStateWithoutEligibility,
          ),
        })),
      Error,
      "Backup eligibility",
    );

    await assertRejects(
      () =>
        verifyRegistrationResponse({
          ...registrationVerification(),
          expectedAlgorithms: [RSASSA_PKCS1_v1_5_SHA_256],
        }),
      Error,
      "Unexpected credential algorithm",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse({
          ...registrationVerification(),
          expectedAlgorithms: undefined,
        }),
      Error,
      "Unexpected credential algorithm",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "unsupported",
            [0xa0],
            parsed.authDataBytes,
          ),
        })),
      Error,
      'Unexpected and unsupported attestation type "unsupported"',
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xa1, ...cborText("sig"), 0x40],
            parsed.authDataBytes,
          ),
        })),
      Error,
      "None attestation is not expected",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xf6],
            parsed.authDataBytes,
          ),
        })),
      Error,
      "Could not verify none attestation",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "packed",
            [0xa1, ...cborText("sig"), ...cborText("bad")],
            parsed.authDataBytes,
          ),
        })),
      Error,
      "Packed attestation signature is malformed",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xa0],
            withCredentialId(parsed.authDataBytes, new Uint8Array()),
          ),
        })),
      Error,
      "Credential ID was not provided",
    );
    await assertRejects(
      () =>
        verifyRegistrationResponse(registrationVerification({
          ...ed25519AttestationResponse(),
          attestationObject: attestationObject(
            "none",
            [0xa0],
            withCredentialId(parsed.authDataBytes, new Uint8Array(1024)),
          ),
        })),
      Error,
      "Credential ID is too long",
    );
  });
});
