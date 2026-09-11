import { assertEquals, assertRejects } from "@std/assert";
import { type CBORType, encodeCBOR } from "@levischuck/tiny-cbor";
import {
  exportPublicKey,
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  type ML_DSA_ALG,
  type ML_DSA_Public_COSE_Key,
} from "@levischuck/tiny-cose";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "./register.ts";
import { verifyAuthenticationResponse } from "./authentication.ts";
import { encodeBase64Url } from "./deps.ts";

type MlDsaName = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";

interface MlDsaCase {
  name: MlDsaName;
  alg: ML_DSA_ALG;
}

const ALGORITHMS: MlDsaCase[] = [
  { name: "ML-DSA-44", alg: ML_DSA_44 },
  { name: "ML-DSA-65", alg: ML_DSA_65 },
  { name: "ML-DSA-87", alg: ML_DSA_87 },
];

const ENCODER = new TextEncoder();
const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const CHALLENGE = new Uint8Array(32).fill(0x42);
const CREDENTIAL_ID = new Uint8Array(32).fill(0x24);
const USER_ID = ENCODER.encode("post-quantum-user");

function concatenate(
  ...chunks: Uint8Array[]
): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(
    chunks.reduce((length, chunk) => length + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function counter(value: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

async function rpIdHash(): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", ENCODER.encode(RP_ID)),
  );
}

function clientData(
  type: "webauthn.create" | "webauthn.get",
): Uint8Array<ArrayBuffer> {
  return ENCODER.encode(JSON.stringify({
    type,
    challenge: encodeBase64Url(CHALLENGE),
    origin: ORIGIN,
    crossOrigin: false,
  }));
}

async function generateCredential(algorithm: MlDsaCase) {
  const keyPair = await crypto.subtle.generateKey(
    { name: algorithm.name },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const publicKey = await exportPublicKey(
    keyPair.publicKey,
  ) as ML_DSA_Public_COSE_Key;
  const coseKey = encodeCBOR(
    new Map<number, CBORType>([
      [1, publicKey.kty],
      [3, publicKey.alg],
      [-1, publicKey.pub],
    ]),
  );
  return { keyPair, coseKey };
}

Deno.test("registration options advertise all ML-DSA algorithms", async () => {
  const options = await generateRegistrationOptions({
    rpName: "Post-quantum RP",
    rpId: RP_ID,
    userName: "post-quantum-user",
    userDisplayName: "Post Quantum User",
    userId: USER_ID,
    supportedAlgorithms: ALGORITHMS.map(({ alg }) => alg),
    challenge: CHALLENGE,
  });

  assertEquals(
    options.pubKeyCredParams,
    ALGORITHMS.map(({ alg }) => ({ type: "public-key", alg })),
  );
});

for (const algorithm of ALGORITHMS) {
  Deno.test(`${algorithm.name} registration and authentication`, async () => {
    const { keyPair, coseKey } = await generateCredential(algorithm);

    const createClientData = clientData("webauthn.create");
    const createClientHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", createClientData),
    );
    const registrationAuthData = concatenate(
      await rpIdHash(),
      new Uint8Array([0x45]), // user present, user verified, attested data
      counter(0),
      new Uint8Array(16), // AAGUID
      new Uint8Array([0, CREDENTIAL_ID.length]),
      CREDENTIAL_ID,
      coseKey,
    );
    const attestationSignature = new Uint8Array(
      await crypto.subtle.sign(
        { name: algorithm.name },
        keyPair.privateKey,
        concatenate(registrationAuthData, createClientHash),
      ),
    );
    const attestationObject = encodeCBOR(
      new Map<string, CBORType>([
        ["fmt", "packed"],
        [
          "attStmt",
          new Map<string, CBORType>([
            ["alg", algorithm.alg],
            ["sig", attestationSignature],
          ]),
        ],
        ["authData", registrationAuthData],
      ]),
    );

    const registration = await verifyRegistrationResponse({
      attestationResponse: {
        clientDataJSON: createClientData.buffer,
        attestationObject: attestationObject.buffer,
      },
      challenge: CHALLENGE,
      expectedAlgorithms: [algorithm.alg],
      origins: [ORIGIN],
      rpId: RP_ID,
    });
    assertEquals(registration.credentialId, CREDENTIAL_ID);
    assertEquals(registration.coseKey, coseKey);

    const getClientData = clientData("webauthn.get");
    const getClientHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", getClientData),
    );
    const authenticationAuthData = concatenate(
      await rpIdHash(),
      new Uint8Array([0x05]), // user present and user verified
      counter(1),
    );
    const assertionSignature = new Uint8Array(
      await crypto.subtle.sign(
        { name: algorithm.name },
        keyPair.privateKey,
        concatenate(authenticationAuthData, getClientHash),
      ),
    );
    const response = {
      authenticatorData: authenticationAuthData,
      clientDataJSON: getClientData,
      signature: assertionSignature,
      userHandle: USER_ID,
    };
    const verification = {
      challenge: CHALLENGE,
      credentialId: CREDENTIAL_ID,
      origins: [ORIGIN],
      rpId: RP_ID,
      response,
      findAccountByUserId: () => Promise.resolve({ userId: USER_ID }),
      findCredential: () =>
        Promise.resolve({
          credentialId: CREDENTIAL_ID,
          publicKey: coseKey,
          signCount: 0,
          userId: USER_ID,
          userVerified: true,
        }),
    };

    const authentication = await verifyAuthenticationResponse(verification);
    assertEquals(authentication.credentialId, CREDENTIAL_ID);
    assertEquals(authentication.signCount, 1);
    assertEquals(authentication.userVerified, true);

    const invalidSignature = assertionSignature.slice();
    invalidSignature[0] ^= 0xff;
    await assertRejects(
      () =>
        verifyAuthenticationResponse({
          ...verification,
          response: { ...response, signature: invalidSignature },
        }),
      Error,
      "Signature failed",
    );
  });
}
