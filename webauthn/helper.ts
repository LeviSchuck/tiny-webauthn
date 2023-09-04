import { decodeBase64, encodeBase64 } from "./deps.ts";
import {
  AuthenticatorAttestationResponse,
  PublicKeyCredentialCreationOptions,
} from "./types.ts";

const B64_PREFIX = "data:;base64,";

// https://w3c.github.io/webauthn/
// Consider using key names instead see toJSON section

export function stringifyWebAuthnObject(
  options:
    | PublicKeyCredentialCreationOptions
    | AuthenticatorAttestationResponse,
): string {
  return JSON.stringify(options, (_k, v) => {
    if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
      return B64_PREFIX + encodeBase64(v);
    }
    return v;
  });
}

export function parseWebAuthnObject(
  json: string,
): Promise<
  PublicKeyCredentialCreationOptions | AuthenticatorAttestationResponse
> {
  return JSON.parse(json, (_k, v) => {
    if (typeof v == "string" && v.startsWith(B64_PREFIX)) {
      return decodeBase64(v.substring(B64_PREFIX.length));
    }
    return v;
  });
}
