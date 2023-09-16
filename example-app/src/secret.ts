import { decodeBase64Url, encodeBase64Url } from "../../src/deps.ts";

let key: CryptoKey | null = null;

export async function loadSecretKey(secret: string) {
  const SECRET_KEY = await crypto.subtle.importKey(
    "raw",
    decodeBase64Url(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  key = SECRET_KEY;
}

export function getSecretKey(): CryptoKey {
  if (!key) {
    throw new Error("Uninitialized?");
  }
  return key;
}

const ENCODER = new TextEncoder();

export async function usernameToId(username: string): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    getSecretKey(),
    ENCODER.encode(`username:${username}`),
  );
  return new Uint8Array(signature.slice(0, 12));
}

export async function deriveCSRFToken(sessionId: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    getSecretKey(),
    ENCODER.encode(`csrf:${sessionId}`),
  );
  return encodeBase64Url(new Uint8Array(signature.slice(0, 12)));
}

