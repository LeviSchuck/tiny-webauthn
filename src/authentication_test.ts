import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.195.0/assert/mod.ts";
import { describe, it } from "https://deno.land/std@0.195.0/testing/bdd.ts";
import { decodeBase64Url } from "./deps.ts";
import { timingSafeEqual } from "./timingSafeEqual.ts";
import {
  AuthenticatingUser,
  CredentialRecord,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "./authentication.ts";

const CREDENTIAL_ID = decodeBase64Url("OUf0LGAmowUoH8OnTklJAQ");
const RSA_CREDENTIAL_ID = decodeBase64Url(
  "aZfhRcejIPt0GtBAYbBC3SphTx_eegh5S-UX4I6DmmE",
);
const ECDSA_CREDENTIAL_ID = decodeBase64Url(
  "YOgmRpF5PncY0hQtSVEKAqH93RWUHKm_Tq3qJJ3dIyB0qwhBMA34LxbgnaIyZQMWV1J6keFXlYLX6lPtsD0kOQ",
);

const CHALLENGE2 = decodeBase64Url(
  "VDSOpXQrhjj2XkMOH742cBQWhkeiwsrWAcNNoW9ts48",
);
const ECDSA_CHALLENGE = decodeBase64Url(
  "kp_D8m2cSi0do3QFpHvMJPxQxZVfv8aJzi_BrRcALivj9raPFgiOMozsq28UOOz6AAABipCv59iTFWLdAsycMgDAFEs",
);
const RSA_CHALLENGE = decodeBase64Url(
  "Ha5Mw6HEYsH_WhOvm2INV4QwqGy0wL848L8bKg-gmtsqE7qDzfXbaqD-3aohID2FAAABipBCG8yoR_D0VCCeN1JxzN0",
);

const USER_ID = decodeBase64Url("VGFjbw");
const ECDSA_USER_ID = decodeBase64Url("kxVi3QLMnDIAwBRL");
const RSA_USER_ID = decodeBase64Url("qEfw9FQgnjdScczd");

// deno-lint-ignore require-await
async function findCredential(
  id: Uint8Array,
): Promise<CredentialRecord | null> {
  if (timingSafeEqual(CREDENTIAL_ID, id)) {
    return {
      credentialId: CREDENTIAL_ID,
      publicKey: decodeBase64Url(
        "pAEBAycgBiFYIHAYBh3a4RSiuvcSN61MILzWN3yPTbHIJoMeGDXqqK_L",
      ),
      signCount: 1,
      userId: USER_ID,
      userVerified: true,
    };
  } else if (timingSafeEqual(ECDSA_CREDENTIAL_ID, id)) {
    return {
      credentialId: ECDSA_CREDENTIAL_ID,
      publicKey: decodeBase64Url(
        "pQECAyYgASFYIOHjf4yPYpZYPLT-wIn8aDry2ttdGncn3ZdGz2t2yE7pIlggXvIXvseyxevMfWnbiAH7q6a6P-FTM5Iu6_y1SI33RPg",
      ),
      signCount: 1,
      userId: ECDSA_USER_ID,
      userVerified: false,
    };
  } else if (timingSafeEqual(RSA_CREDENTIAL_ID, id)) {
    return {
      credentialId: RSA_CREDENTIAL_ID,
      publicKey: decodeBase64Url(
        "pAEDAzkBACBZAQCaw0WWX2Fo63TU8fxFVCiKkyF72bTFcz8w9I8airxBiuf3K4OM7DipWfHkHxJy4wviGXDrF--7I34WFn0gQBYWZssJp8uSzv4teR0W7flhs_VMZuR6kBVGncf5pFh8sD0O3qHF4npncbzebtqyMaThXDrYs1FrpqmsYns33SEvtuwwc05-VilMo1pNFJqqqXJ2b8vWNeeznJvT7zoae-tdMyUEPbCdus4N1rHOJ0cV_QqE0__I8AkN7lO32NV7P36ZFHEw0CbQuieK-W-_VGyG5u8pULEpB-d38JWgQ_Tj7ZlPS4bsntoTi3S5zGp_qEnFtZD9YJ3cieHVnwZjWvq3IUMBAAE",
      ),
      signCount: 0,
      userId: RSA_USER_ID,
      userVerified: true,
    };
  }
  return null;
}

// deno-lint-ignore require-await
async function findAuthenticatingUser(): Promise<AuthenticatingUser | null> {
  return {
    userId: USER_ID,
  };
}

// deno-lint-ignore require-await
async function findAccountByUserId(
  userId: Uint8Array,
): Promise<AuthenticatingUser | null> {
  if (timingSafeEqual(userId, USER_ID)) {
    return {
      userId: USER_ID,
    };
  } else if (timingSafeEqual(userId, ECDSA_USER_ID)) {
    return {
      userId: ECDSA_USER_ID,
    };
  } else if (timingSafeEqual(userId, RSA_USER_ID)) {
    return {
      userId: RSA_USER_ID,
    };
  }
  return null;
}

describe("Authentication", () => {
  it("Can generate verification options", async () => {
    const options = await generateAuthenticationOptions({
      rpId: "levischuck.com",
      challenge: CHALLENGE2,
    });
    assert(timingSafeEqual(CHALLENGE2, options.challenge));
    assertEquals(options.rpId, "levischuck.com");
    assertEquals(options.allowCredentials, []);
  });

  it("Can verify an Ed25519 authentication with pre-known user", async () => {
    const verified = await verifyAuthenticationResponse({
      challenge: CHALLENGE2,
      credentialId: CREDENTIAL_ID,
      origin: ["https://levischuck.com"],
      rpId: "levischuck.com",
      response: {
        userHandle: USER_ID.buffer,
        authenticatorData:
          decodeBase64Url("GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgkFAAAABA")
            .buffer,
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVkRTT3BYUXJoamoyWGtNT0g3NDJjQlFXaGtlaXdzcldBY05Ob1c5dHM0OCIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ",
        ).buffer,
        signature: decodeBase64Url(
          "V5YJBn-Bd6-hxp7Yf6u8sxP3orgcE3pcnL5SoaJaSxuqcnkDC2qgc1XUrG320o91bdbQBuVsp6LyUCHBhfFMDg",
        ).buffer,
      },
      findAuthenticatingUser,
      findCredential,
    });
    assert(timingSafeEqual(verified.credentialId, CREDENTIAL_ID));
    assertEquals(verified.signCount, 4);
    assertEquals(verified.authenticatingUser.userId, USER_ID);
    assertEquals(verified.userVerified, true);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
  });

  it("Can verify an Ed25519 authentication with dynamically found user", async () => {
    const verified = await verifyAuthenticationResponse({
      challenge: CHALLENGE2,
      credentialId: CREDENTIAL_ID,
      origin: ["https://levischuck.com"],
      rpId: "levischuck.com",
      response: {
        userHandle: USER_ID.buffer,
        authenticatorData:
          decodeBase64Url("GX3XEkLc5hSbg4PrSibs8QePOaZxVoZYVHuCR7T-AgkFAAAABA")
            .buffer,
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVkRTT3BYUXJoamoyWGtNT0g3NDJjQlFXaGtlaXdzcldBY05Ob1c5dHM0OCIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXNjaHVjay5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ",
        ).buffer,
        signature: decodeBase64Url(
          "V5YJBn-Bd6-hxp7Yf6u8sxP3orgcE3pcnL5SoaJaSxuqcnkDC2qgc1XUrG320o91bdbQBuVsp6LyUCHBhfFMDg",
        ).buffer,
      },
      findAccountByUserId,
      findCredential,
    });
    assert(timingSafeEqual(verified.credentialId, CREDENTIAL_ID));
    assertEquals(verified.signCount, 4);
    assertEquals(verified.authenticatingUser.userId, USER_ID);
    assertEquals(verified.userVerified, true);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
  });

  it("Can verify an ES256 authentication", async () => {
    const verified = await verifyAuthenticationResponse({
      challenge: ECDSA_CHALLENGE,
      credentialId: ECDSA_CREDENTIAL_ID,
      origin: ["https://localhost:8443"],
      rpId: "localhost",
      response: {
        userHandle: ECDSA_USER_ID.buffer,
        authenticatorData:
          decodeBase64Url("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAABQ")
            .buffer,
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoia3BfRDhtMmNTaTBkbzNRRnBIdk1KUHhReFpWZnY4YUp6aV9CclJjQUxpdmo5cmFQRmdpT01venNxMjhVT096NkFBQUJpcEN2NTlpVEZXTGRBc3ljTWdEQUZFcyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        ).buffer,
        signature: decodeBase64Url(
          "MEYCIQCBQn9VVsxLoC6EWYuU1euw5hFrNyBO2FUQT-VQ_whSvAIhAN0aYIYfg5mfcgfRkaKWdrNx8VDolRBt8j1ZspsYARRh",
        ).buffer,
      },
      findAccountByUserId,
      findCredential,
    });
    assert(timingSafeEqual(verified.credentialId, ECDSA_CREDENTIAL_ID));
    assertEquals(verified.signCount, 5);
    assertEquals(verified.authenticatingUser.userId, ECDSA_USER_ID);
    assertEquals(verified.userVerified, true);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
  });
  it("Can verify an RS256 authentication", async () => {
    const verified = await verifyAuthenticationResponse({
      challenge: RSA_CHALLENGE,
      credentialId: RSA_CREDENTIAL_ID,
      origin: ["https://levis-macbook-pro.local:8443"],
      rpId: "levis-macbook-pro.local",
      response: {
        userHandle: RSA_USER_ID.buffer,
        authenticatorData:
          decodeBase64Url("umjb-DO4Ys8D89B336x6RG3r8LuXhC1vRBAFcAoKhNgFAAAAAQ")
            .buffer,
        clientDataJSON: decodeBase64Url(
          "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSGE1TXc2SEVZc0hfV2hPdm0ySU5WNFF3cUd5MHdMODQ4TDhiS2ctZ210c3FFN3FEemZYYmFxRC0zYW9oSUQyRkFBQUJpcEJDRzh5b1JfRDBWQ0NlTjFKeHpOMCIsIm9yaWdpbiI6Imh0dHBzOi8vbGV2aXMtbWFjYm9vay1wcm8ubG9jYWw6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
        ).buffer,
        signature: decodeBase64Url(
          "MQoPc-toEJfnkC70BeDJUICHMoVMafl9WjFsRfT9ICzToa4OtLY83Eu7kO67VjxicCQCuKHjbS9qPlva0PN5TfeMaxcewfHSaA6wkxVtjurPIVHE1vR6Kxg1Huv5-amNNFrYabTXq111J6gBy8NGbtQDXBq1VAUTypM21ZikUykkWi79D-ebWaodBI6shK-PJCQRfHqZej2Hc2Ra3pnlcRV1n-ktqwRng5wv0XLt4FAA3kJE4l8AIVguiicMx7obJ52ErUVKQIXxdMEqrOSSRTLCKfmF0oRXtK9ObHXKvWArabjJENHPsSv7MlNw_KyRUewq2fYz741-0LYlG0C8Yg",
        ).buffer,
      },
      findAccountByUserId,
      findCredential,
    });
    assert(timingSafeEqual(verified.credentialId, RSA_CREDENTIAL_ID));
    assertEquals(verified.signCount, 1);
    assertEquals(verified.authenticatingUser.userId, RSA_USER_ID);
    assertEquals(verified.userVerified, true);
    assertEquals(verified.backupState, false);
    assertEquals(verified.multiDevice, false);
  });
});
