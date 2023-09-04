import {
  ECDSA_SHA_256,
  ECDSA_SHA_384,
  ECDSA_SHA_512,
  RSASSA_PKCS1_v1_5_SHA_256,
  RSASSA_PKCS1_v1_5_SHA_384,
  RSASSA_PKCS1_v1_5_SHA_512,
} from "./deps.ts";
import { CreateAuthenticatorResponse } from "./types.ts";

export interface AttestationVerifier {
  verify(
    create: CreateAuthenticatorResponse,
    hash: Uint8Array,
    key: CryptoKey,
  ): Promise<boolean>;
}

export class NoneAttestationVerifier implements AttestationVerifier {
  verify(
    create: CreateAuthenticatorResponse,
    _hash: Uint8Array,
    _key: CryptoKey,
  ): Promise<boolean> {
    // Nothing to verify for "none"
    if (create.attStmt instanceof Map) {
      if (create.attStmt.size > 0) {
        throw new Error(
          "None attestation is not expected to send any attestation statement",
        );
      }
      return Promise.resolve(true);
    } else {
      return Promise.resolve(false);
    }
  }
}

export class PackedAttestationVerifier implements AttestationVerifier {
  async verify(
    create: CreateAuthenticatorResponse,
    hash: Uint8Array,
    key: CryptoKey,
  ): Promise<boolean> {
    const attStmt = create.attStmt;
    const authData = create.authData;
    if (attStmt instanceof Map) {
      // Only implementing self signatures, x5c is not implemented
      // Also, any reset yubikeys will provide the x5c chain for it's previous key
      // and present a new unrelated key.

      const sig = attStmt.get("sig") as Uint8Array;
      if (!(sig instanceof Uint8Array)) {
        throw new Error("Packed attestation signature is malformed");
      }

      const alg = authData.attestedCredentialData?.credentialPublicKey.alg;
      if (!alg) {
        // Unreachable in normal operation
        throw new Error("Missing key algorithm");
      }

      // Prepare signed data
      const signedData = new Uint8Array(
        create.authDataBytes.length + hash.length,
      );
      signedData.set(create.authDataBytes, 0);
      signedData.set(hash, create.authDataBytes.length);

      if (
        alg == RSASSA_PKCS1_v1_5_SHA_256 || alg == RSASSA_PKCS1_v1_5_SHA_384 ||
        alg == RSASSA_PKCS1_v1_5_SHA_512
      ) {
        return await crypto.subtle.verify(
          { name: "RSASSA-PKCS1-v1_5" },
          key,
          sig,
          signedData,
        );
      } else if (alg == ECDSA_SHA_256) {
        return await crypto.subtle.verify(
          { name: "ECDSA", hash: { name: "SHA-256" } },
          key,
          sig,
          signedData,
        );
      } else if (alg == ECDSA_SHA_384) {
        return await crypto.subtle.verify(
          { name: "ECDSA", hash: { name: "SHA-384" } },
          key,
          sig,
          signedData,
        );
      } else if (alg == ECDSA_SHA_512) {
        return await crypto.subtle.verify(
          { name: "ECDSA", hash: { name: "SHA-512" } },
          key,
          sig,
          signedData,
        );
      }
      throw new Error("Packed attestation algorithm not supported");
    } else {
      return false;
    }
  }
}
