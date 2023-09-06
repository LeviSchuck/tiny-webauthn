import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import { decodeBase64Url } from "./deps.ts";
import { timingSafeEqual } from "https://deno.land/std@0.160.0/crypto/timing_safe_equal.ts";
import { AuthenticatingUser, CredentialRecord, generateAuthenticationOptions, verifyAuthenticationResponse } from "./authentication.ts";


const CREDENTIAL_ID = decodeBase64Url('OUf0LGAmowUoH8OnTklJAQ');
const CHALLENGE2 = decodeBase64Url(
  "VDSOpXQrhjj2XkMOH742cBQWhkeiwsrWAcNNoW9ts48",
);

const USER_HANDLE = decodeBase64Url('VGFjbw');
const USER_ID = decodeBase64Url('VGFjbw');

// deno-lint-ignore require-await
async function findCredential(id: Uint8Array) : Promise<CredentialRecord | null> {
  if (timingSafeEqual(CREDENTIAL_ID, id)) {
    return {
      credentialId: CREDENTIAL_ID,
      publicKey: decodeBase64Url('pAEBAycgBiFYIHAYBh3a4RSiuvcSN61MILzWN3yPTbHIJoMeGDXqqK_L'),
      signCount: 1,
      userHandle: USER_HANDLE,
      userId: USER_ID,
      userVerified: true
    }
  }
  return null;
}

// deno-lint-ignore require-await
async function findAuthenticatingUser() : Promise<AuthenticatingUser | null> {
  return {
    userHandle: USER_HANDLE,
    userId: USER_ID
  };
}

// deno-lint-ignore require-await
async function findAccountByUserHandle(userHandle: Uint8Array) : Promise<AuthenticatingUser | null> {
  if (timingSafeEqual(userHandle, USER_HANDLE)) {
    return {
      userHandle: USER_HANDLE,
      userId: USER_ID
    }
  }
  return null;
}



describe("Authentication", () => {
  it("Can generate verification options", async () => {
    const options = await generateAuthenticationOptions({
      rpId: "levischuck.com",
      challenge: CHALLENGE2
    });
    assert(timingSafeEqual(CHALLENGE2, options.challenge))
    assertEquals(options.rpId, "levischuck.com");
    assertEquals(options.allowCredentials, []);
  });

  it("Can verify an authentication with pre-known user", async () => {
    const verified = await verifyAuthenticationResponse({
      challenge: CHALLENGE2,
      credentialId: CREDENTIAL_ID,
      origin: 'https://levischuck.com',
      rpId: 'levischuck.com',
      response: {
        userHandle: USER_HANDLE.buffer,
        authenticatorData: decodeBase64Url('GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgkFAAAABA').buffer,
        clientDataJSON: decodeBase64Url('eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVkRTT3BYUXJoamoyWGtNT0g3NDJjQlFXaGtlaXdzcldBY05Ob1c5dHM0OCIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ').buffer,
        signature: decodeBase64Url('V5YJBn-Bd6-hxp7Yf6u8sxP3orgcE3pcnL5SoaJaSxuqcnkDC2qgc1XUrG320o91bdbQBuVsp6LyUCHBhfFMDg').buffer
      },
      findAuthenticatingUser,
      findCredential,
    });
    assert(timingSafeEqual(verified.credentialId, CREDENTIAL_ID));
    assertEquals(verified.signCount, 4);
    assertEquals(verified.authenticatingUser.userHandle, USER_HANDLE)
    assertEquals(verified.authenticatingUser.userId, USER_ID);
    assertEquals(verified.userVerified, true);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
  });

  it("Can verify an authentication with dynamically found user", async () => {
    const verified = await verifyAuthenticationResponse({
      challenge: CHALLENGE2,
      credentialId: CREDENTIAL_ID,
      origin: 'https://levischuck.com',
      rpId: 'levischuck.com',
      response: {
        userHandle: USER_HANDLE.buffer,
        authenticatorData: decodeBase64Url('GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgkFAAAABA').buffer,
        clientDataJSON: decodeBase64Url('eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVkRTT3BYUXJoamoyWGtNT0g3NDJjQlFXaGtlaXdzcldBY05Ob1c5dHM0OCIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ').buffer,
        signature: decodeBase64Url('V5YJBn-Bd6-hxp7Yf6u8sxP3orgcE3pcnL5SoaJaSxuqcnkDC2qgc1XUrG320o91bdbQBuVsp6LyUCHBhfFMDg').buffer
      },
      findAccountByUserHandle,
      findCredential,
    });
    assert(timingSafeEqual(verified.credentialId, CREDENTIAL_ID));
    assertEquals(verified.signCount, 4);
    assertEquals(verified.authenticatingUser.userHandle, USER_HANDLE)
    assertEquals(verified.authenticatingUser.userId, USER_ID);
    assertEquals(verified.userVerified, true);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
  });
})