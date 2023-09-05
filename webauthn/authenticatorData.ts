import { decodePartialCBOR, parseCBORToCOSEKey } from "./deps.ts";
import { AuthenticatorData } from "./types.ts";

export function parseAuthenticatorData(data: ArrayBuffer): AuthenticatorData {
  const view = new DataView(data);
  const flags = view.getUint8(32);

  const result: AuthenticatorData = {
    rpIdHash: new Uint8Array(data.slice(0, 32)),
    extensionDataIncluded: (flags & 0b1000_0000) != 0,
    attestedCredentialDataIncluded: (flags & 0b0100_0000) != 0,
    backupState: (flags & 0b0001_0000) != 0,
    backupEligibility: (flags & 0b0000_1000) != 0,
    userVerified: (flags & 0b0000_0100) != 0,
    userPresent: (flags & 0b0000_0001) != 0,
    signCount: view.getUint32(33, false),
  };
  let offset = 37;
  if (data.byteLength > offset && result.attestedCredentialDataIncluded) {
    const aaguid = new Uint8Array(data.slice(offset, offset + 16));
    offset += 16;
    const credentialIdLength = view.getUint16(offset);
    offset += 2;
    const credentialId = new Uint8Array(
      data.slice(offset, offset + credentialIdLength),
    );
    offset += credentialIdLength;
    const [pubKeyCbor, length] = decodePartialCBOR(view, offset);
    // Some trickery is required to extract a slice of the relevant bytes
    const credentialPublicKeyBytesView = new Uint8Array(data, offset, length);
    const credentialPublicKeyBytes = new Uint8Array(length);
    credentialPublicKeyBytes.set(credentialPublicKeyBytesView);
    offset += length;
    const key = parseCBORToCOSEKey(pubKeyCbor);
    if (key.alg) {
      result.attestedCredentialData = {
        aaguid,
        credentialId,
        credentialPublicKey: key,
        credentialPublicKeyBytes,
      };
    }
  }
  if (data.byteLength >= offset && result.extensionDataIncluded) {
    const extensions = decodePartialCBOR(view, offset);
    result.extensions = extensions;
  }
  return result;
}
