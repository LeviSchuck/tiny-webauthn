import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import {
  NoneAttestationVerifier,
  PackedAttestationVerifier,
} from "./attestation.ts";
import { type CBORType, EDDSA } from "./deps.ts";
import type { CreateAuthenticatorResponse } from "./types.ts";

const HASH = new Uint8Array(32);
const AUTH_DATA_BYTES = new Uint8Array([1, 2, 3]);

async function key(): Promise<CryptoKey> {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  return pair.publicKey;
}

function create(
  attStmt: unknown,
  alg: number | null = EDDSA,
): CreateAuthenticatorResponse {
  return {
    fmt: "packed",
    attStmt: attStmt as CBORType,
    authData: {
      rpIdHash: new Uint8Array(32),
      extensionDataIncluded: false,
      attestedCredentialDataIncluded: true,
      backupState: false,
      backupEligibility: false,
      userVerified: false,
      userPresent: true,
      signCount: 0,
      attestedCredentialData: alg == null ? undefined : {
        aaguid: new Uint8Array(16),
        credentialId: new Uint8Array([1]),
        credentialPublicKey: { alg } as never,
        credentialPublicKeyBytes: new Uint8Array([1]),
      },
    },
    authDataBytes: AUTH_DATA_BYTES,
  };
}

describe("Attestation verifiers", () => {
  it("accepts empty none attestation statements", async () => {
    const verified = await new NoneAttestationVerifier().verify(
      create(new Map(), EDDSA),
      HASH,
      await key(),
    );
    assert(verified);
  });

  it("rejects non-empty none attestation statements", async () => {
    const publicKey = await key();
    assertThrows(
      () =>
        new NoneAttestationVerifier().verify(
          create(new Map([["sig", new Uint8Array()]]), EDDSA),
          HASH,
          publicKey,
        ),
      Error,
      "None attestation is not expected",
    );
  });

  it("returns false for non-map attestation statements", async () => {
    const publicKey = await key();
    assertEquals(
      await new NoneAttestationVerifier().verify(create(null), HASH, publicKey),
      false,
    );
    assertEquals(
      await new PackedAttestationVerifier().verify(
        create(null),
        HASH,
        publicKey,
      ),
      false,
    );
  });

  it("rejects malformed packed signatures", async () => {
    await assertRejects(
      async () =>
        await new PackedAttestationVerifier().verify(
          create(new Map([["sig", "not bytes"]])),
          HASH,
          await key(),
        ),
      Error,
      "Packed attestation signature is malformed",
    );
  });

  it("rejects packed attestations without a key algorithm", async () => {
    await assertRejects(
      async () =>
        await new PackedAttestationVerifier().verify(
          create(new Map([["sig", new Uint8Array()]]), null),
          HASH,
          await key(),
        ),
      Error,
      "Missing key algorithm",
    );
  });

  it("returns false when a packed self-signature does not verify", async () => {
    const verified = await new PackedAttestationVerifier().verify(
      create(new Map([["sig", new Uint8Array(64)]])),
      HASH,
      await key(),
    );
    assertEquals(verified, false);
  });
});
