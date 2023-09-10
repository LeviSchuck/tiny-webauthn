import { encodeHex } from "https://deno.land/x/tiny_encodings@0.2.1/encoding.ts";
import {
  ALG_ALL,
  ECDSA_ALG,
  ECDSA_SHA_256,
  EDDSA,
  RSASSA_PKCS1_v1_5_SHA_256,
} from "./deps.ts";

function decodeAsn1Integer(view: DataView, offset: number): [number, number] {
  const length = view.getUint8(offset);
  if (length & 0b1000_0000) {
    const lengthBytes = length & 0b0111_1111;
    if (lengthBytes > 2) {
      throw new Error("Unexpected asn.1 length");
    }
    if (lengthBytes == 1) {
      return [view.getUint8(offset + 1), 2];
    } else if (lengthBytes == 0) {
      throw new Error("Indefinite lengths are not supported");
    }
    return [view.getUint16(offset + 1), 3];
  } else {
    return [length, 1];
  }
}

export function unwrapAsn1EC2Signature(
  sig: Uint8Array,
  alg: ECDSA_ALG,
): Uint8Array {
  const size = 32;
  // Vary size depending on algorithm
  if (alg != ECDSA_SHA_256) {
    throw new Error("Unsupported algorithm");
  }
  const output = new Uint8Array(size * 2);

  if (sig[0] != 0x30) {
    throw new Error("Signature is not asn.1");
  }
  let offset = 1;
  const view = new DataView(sig.buffer);
  const [contentsLength, contentsOffset] = decodeAsn1Integer(view, offset);
  offset += contentsOffset;
  if (sig.byteLength != offset + contentsLength) {
    throw new Error("Corrupted asn.1");
  }
  // r in [r, s]
  if (view.getUint8(offset) != 2) {
    throw new Error("Signature is not asn.1");
  }
  offset++;
  const [rLength, rOffset] = decodeAsn1Integer(view, offset);
  offset += rOffset;
  if (rLength == size + 1 && view.getUint8(offset) == 0) {
    // Sometimes there is a leading 0 on these things
  } else if (rLength > size) {
    throw new Error(
      `Corrupted signature, r component is too long. Expected ${size} bytes, got ${rLength} bytes`,
    );
  }
  output.set(
    new Uint8Array(sig.buffer, offset + (rLength > size ? 1 : 0), size),
    size - rLength + (rLength > size ? 1 : 0),
  );
  offset += rLength;

  // s in [r, s]
  if (view.getUint8(offset) != 2) {
    throw new Error("Signature is not asn.1");
  }
  offset++;
  const [sLength, sOffset] = decodeAsn1Integer(view, offset);
  offset += sOffset;
  if (sLength == size + 1 && view.getUint8(offset) == 0) {
    // Sometimes there is a leading 0 on these things
  } else if (sLength > size) {
    throw new Error(
      `Corrupted signature, s component is too long. Expected ${size} bytes, got ${sLength} bytes`,
    );
  }
  output.set(
    new Uint8Array(sig.buffer, offset + (sLength > size ? 1 : 0), size),
    size + size - sLength + (sLength > size ? 1 : 0),
  );
  offset += sLength;

  return output;
}

export async function verifySignature(
  alg: ALG_ALL,
  key: CryptoKey,
  sig: Uint8Array,
  signedData: Uint8Array,
): Promise<boolean> {
  console.log(`Incoming signature with length: ${sig.length}`);
  if (
    alg == RSASSA_PKCS1_v1_5_SHA_256
  ) {
    return await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      sig,
      signedData,
    );
  } else if (alg == ECDSA_SHA_256) {
    console.log(`Sig: ${encodeHex(sig)}`);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      key,
      unwrapAsn1EC2Signature(sig, alg),
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
