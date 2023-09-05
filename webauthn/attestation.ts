import { CreateAuthenticatorResponse } from "./types.ts";
import { verifySignature } from "./verifier.ts";

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

      return await verifySignature(alg, key, sig, signedData);
    } else {
      return false;
    }
  }
}
