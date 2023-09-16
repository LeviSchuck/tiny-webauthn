import { getSecretKey } from "./secret.ts";

async function signChallenge(
  challenge: Uint8Array,
): Promise<Uint8Array> {
  const signtature = await crypto.subtle.sign(
    { name: "HMAC" },
    getSecretKey(),
    challenge,
  );
  return new Uint8Array(signtature);
}

export async function assembleChallenge(
  random: Uint8Array,
  expiration: number,
  id: Uint8Array,
) {
  if (random.length != 16) {
    throw new Error("Expected random to be 16 bytes");
  }
  const dataToSign = new Uint8Array(
    16 + 8 + id.length,
  );
  dataToSign.set(random, 0);
  const view = new DataView(dataToSign.buffer);
  view.setBigUint64(random.length, BigInt(expiration));
  dataToSign.set(id, random.length + 8);
  const signature = await signChallenge(dataToSign);
  const challenge = new Uint8Array(signature.length + dataToSign.length);
  challenge.set(signature, 0);
  challenge.set(dataToSign, signature.length);
  return challenge;
}

export async function disassembleAndVerifyChallenge(
  challenge: Uint8Array,
): Promise<{ userId: Uint8Array; expiration: number }> {
  // console.log(challenge);
  const signature = new Uint8Array(32);
  signature.set(new Uint8Array(challenge.buffer, 0, 32), 0);
  const dataToSign = new Uint8Array(challenge.length - 32);
  dataToSign.set(new Uint8Array(challenge.buffer, 32));
  const verify = await crypto.subtle.verify(
    { name: "HMAC" },
    getSecretKey(),
    signature,
    dataToSign,
  );
  if (!verify) {
    throw new Error("Could not verify challenge met expectations");
  }
  const view = new DataView(dataToSign.buffer, 0);
  const expiration = view.getBigUint64(16, false);
  if (expiration < 0 && expiration > Number.MAX_SAFE_INTEGER) {
    throw new Error("Expiration is out of bounds");
  }
  const userId = new Uint8Array(12);
  userId.set(new Uint8Array(dataToSign.buffer, 16 + 8));
  return {
    expiration: Number(expiration),
    userId,
  };
}
