import {
  ALG_ALL,
  ECDSA_SHA_256,
  ECDSA_SHA_384,
  ECDSA_SHA_512,
  EDDSA,
  RSASSA_PKCS1_v1_5_SHA_256,
  RSASSA_PKCS1_v1_5_SHA_384,
  RSASSA_PKCS1_v1_5_SHA_512,
} from "./deps.ts";

export async function verifySignature(
  alg: ALG_ALL,
  key: CryptoKey,
  sig: Uint8Array,
  signedData: Uint8Array,
): Promise<boolean> {
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
  } else if (alg == EDDSA) {
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      sig,
      signedData,
    );
  }
  return false;
}
