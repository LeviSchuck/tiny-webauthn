import {
  AuthenticatorAttestationResponse,
  COSEAlgorithmIdentifier,
  CreateAuthenticatorResponse,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialDescriptor,
} from "./types.ts";
import {
  CBORType,
  decodeBase64Url,
  decodeCBOR,
  importPublicKey,
} from "./deps.ts";
import { timingSafeEqual } from "./timingSafeEqual.ts";
import {
  AttestationVerifier,
  NoneAttestationVerifier,
  PackedAttestationVerifier,
} from "./attestation.ts";
import { parseAuthenticatorData } from "./authenticatorData.ts";

export interface RegistrationOptions {
  rpName: string;
  rpId?: string;
  userName: string;
  userDisplayName: string;
  userId: Uint8Array;
  userVerification?: boolean;
  kind?: "passkey" | "server-side";
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  supportedAlgorithms?: COSEAlgorithmIdentifier[];
  challenge?: Uint8Array;
}

export interface RegistrationVerification {
  attestationResponse: AuthenticatorAttestationResponse;
  rpId: string;
  origin: string;
  challenge: Uint8Array;
  expectUserVerification?: true;
  expectedAlgorithms: COSEAlgorithmIdentifier[];
}

interface WebAuthnCreateData {
  type: "webauthn.create";
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  topOrigin?: string;
}

export interface WebAuthnCreateResponse {
  credentialId: Uint8Array;
  coseKey: Uint8Array;
  extensions?: CBORType;
  multiDevice: boolean;
  backupState: boolean;
  userVerified: boolean;
  signCount: number;
  clientDataJSON: Uint8Array;
  attestationObject: Uint8Array;
}

// deno-lint-ignore require-await
export async function generateRegistrationOptions(
  options: RegistrationOptions,
): Promise<PublicKeyCredentialCreationOptions> {
  let challenge = crypto.getRandomValues(new Uint8Array(32));
  if (options.challenge) {
    challenge = options.challenge;
    if (challenge.length < 16) {
      throw new Error("Insufficient challenge size");
    }
  }
  const result: PublicKeyCredentialCreationOptions = {
    challenge,
    rp: {
      name: options.rpName,
    },
    user: {
      name: options.userName,
      id: options.userId,
      displayName: options.userDisplayName,
    },
    pubKeyCredParams: [{
      alg: -7,
      type: "public-key",
    }, {
      alg: -257,
      type: "public-key",
    }],
    attestation: "none",
    excludeCredentials: [],
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "preferred",
    },
  };

  if (options.supportedAlgorithms) {
    result.pubKeyCredParams = options.supportedAlgorithms.map((alg) => ({
      type: "public-key",
      alg,
    }));
  }

  if (options.rpId) {
    result.rp.id = options.rpId;
  }

  if (options.extensions) {
    result.extensions = options.extensions;
  }

  if (result.authenticatorSelection) {
    if (options.kind == "passkey") {
      result.authenticatorSelection.residentKey = "required";
      result.authenticatorSelection.requireResidentKey = true;
      if (result.extensions) {
        // deno-lint-ignore no-explicit-any
        (result.extensions as any).credProps = true;
      } else {
        result.extensions = { credProps: true };
      }
    } else if (options.kind == "server-side") {
      result.authenticatorSelection.residentKey = "discouraged";
    }
    if (options.userVerification != null) {
      result.authenticatorSelection.userVerification = options.userVerification
        ? "required"
        : "discouraged";
    }
  }
  if (options.excludeCredentials) {
    result.excludeCredentials = options.excludeCredentials;
  }

  return result;
}

export function parseCreateResponse(
  data: ArrayBuffer,
): CreateAuthenticatorResponse {
  const cbor = decodeCBOR(data);
  if (!(cbor instanceof Map)) {
    throw new Error("Malformed create response");
  }
  const fmt = cbor.get("fmt");
  const attStmt = cbor.get("attStmt");
  const authData = cbor.get("authData");
  if (!(authData instanceof Uint8Array)) {
    throw new Error("Malformed create response");
  }
  const parsedAuthData = parseAuthenticatorData(authData.buffer);
  return {
    fmt,
    attStmt,
    authData: parsedAuthData,
    authDataBytes: authData,
  };
}

const DECODER = new TextDecoder();
const ENCODER = new TextEncoder();

export async function verifyRegistrationResponse(
  options: RegistrationVerification,
): Promise<WebAuthnCreateResponse> {
  // Steps are primarily pulled from the editors draft https://w3c.github.io/webauthn/
  // Equivalent steps are documented from https://www.w3.org/TR/webauthn-3/
  // Step 1 - call generateRegistrationOptions above
  // Step 2 - Client side - call navigator.credentials.create({publicKey: ...})
  // Step 3 - Client side - collect credential.response
  // Step 4 - Client side - collect clientExtensionResults()
  // Step 5 - Client side - collect clientDataJSON
  if (
    !options.attestationResponse.clientDataJSON ||
    options.attestationResponse.clientDataJSON.byteLength == 0
  ) {
    throw new Error("clientDataJSON must be provided");
  }
  // Step 6 - Parse clientDataJSON
  const clientData = JSON.parse(
    DECODER.decode(options.attestationResponse.clientDataJSON),
  ) as WebAuthnCreateData;

  // Step 7 - check that type is webauthn.create
  if (clientData.type != "webauthn.create") {
    throw new Error(
      `Expected type to be "webauthn.create", not "${clientData.type}"`,
    );
  }
  // Step 8 - check that the challenge matches
  if (
    !clientData.challenge || !timingSafeEqual(
      decodeBase64Url(clientData.challenge),
      options.challenge,
    )
  ) {
    console.log(clientData.challenge);
    throw new Error("Challenge does not match what is expected");
  }
  // Step 9 - check that the origin is expected
  if (clientData.origin != options.origin) {
    throw new Error(
      `Expected origin to be "${options.origin}", but was "${clientData.origin}"`,
    );
  }
  // Step 10 - topOrigin is not expected so error out
  if (clientData.topOrigin) {
    throw new Error("Unexpected topOrigin");
  }
  // Step 11 - Hash the JSON bytes
  const hash = await crypto.subtle.digest(
    { name: "SHA-256" },
    options.attestationResponse.clientDataJSON,
  );

  // Step 12 - Decode the attestation object and so on
  const createResponse = await parseCreateResponse(
    options.attestationResponse.attestationObject,
  );
  const authenticatorData = createResponse.authData;
  if (!authenticatorData.attestedCredentialData) {
    throw new Error("No authenticator data found");
  }

  // Step 13
  const expectedRpIdHash = await crypto.subtle.digest(
    { name: "SHA-256" },
    ENCODER.encode(options.rpId),
  );
  if (!timingSafeEqual(expectedRpIdHash, authenticatorData.rpIdHash)) {
    throw new Error("Relying Party ID mismatch");
  }

  // Step 14
  if (!authenticatorData.userPresent) {
    throw new Error("Expected user presence");
  }

  // Step 15
  // This is the last step where numbers are aligned between
  // https://www.w3.org/TR/webauthn-3/ and
  // https://w3c.github.io/webauthn/ the editors draft
  if (options.expectUserVerification && !authenticatorData.userVerified) {
    throw new Error("Expected user verified");
  }

  // Step 16
  if (!authenticatorData.backupEligibility && authenticatorData.backupState) {
    throw new Error(
      "Backup eligibility and state are not expected to be false and true respectively.",
    );
  }

  // Step 17 - Backup eligibility - skipped
  // Not present in https://www.w3.org/TR/webauthn-3/

  // Step 18 - Backup state - skipped
  // Not present in https://www.w3.org/TR/webauthn-3/

  // Step 19 - Expected algorithm
  // Also known as step 16 in https://www.w3.org/TR/webauthn-3/
  const credentialAlg =
    authenticatorData.attestedCredentialData.credentialPublicKey.alg;
  if (
    (credentialAlg != -7 && credentialAlg != -257 && credentialAlg != -8) ||
    options.expectedAlgorithms.indexOf(credentialAlg) === -1
  ) {
    throw new Error(`Unexpected credential algorithm ${credentialAlg}`);
  }

  const { key } = await importPublicKey(
    authenticatorData.attestedCredentialData.credentialPublicKey,
  );

  // Step 20 - Verify client extensions meet expectations
  // Also known as step 17 in https://www.w3.org/TR/webauthn-3/
  // skipped - no extensions supported

  // Step 21 - Check on fmt using case sensitive comparison
  // Also known as step 18 in https://www.w3.org/TR/webauthn-3/
  let verifier: AttestationVerifier;
  if (createResponse.fmt == "none") {
    verifier = new NoneAttestationVerifier();
  } else if (createResponse.fmt == "packed") {
    verifier = new PackedAttestationVerifier();
  } else {
    throw new Error(
      `Unexpected and unsupported attestation type "${createResponse.fmt}"`,
    );
  }

  // Step 22 - Verify attestation statement
  // Also known as step 19 in https://www.w3.org/TR/webauthn-3/
  const verified = verifier.verify(createResponse, new Uint8Array(hash), key);

  if (!verified) {
    throw new Error("Could not verify none attestation");
  }

  // Step 23 - Trust anchors
  // Also known as step 20 in https://www.w3.org/TR/webauthn-3/
  // skipped N/A to attestation "none"
  // No trust path to share

  // Step 24 - Assess trustworthiness of attestation
  // Also known as step 21 in https://www.w3.org/TR/webauthn-3/
  // skipped N/A as attestation "none"

  // Step 25 - verify that credentialId is <= 1023 bytes
  // Not present in https://www.w3.org/TR/webauthn-3/
  if (authenticatorData.attestedCredentialData.credentialId.length == 0) {
    throw new Error("Credential ID was not provided");
  }
  if (authenticatorData.attestedCredentialData.credentialId.length > 1023) {
    throw new Error("Credential ID is too long");
  }

  // Step 26 - verify that the credentialId is not associated for any user
  // Also known as step 22 in https://www.w3.org/TR/webauthn-3/
  // skipped out of scope for this function
  // to be performed after calling this function

  // Step 27 - Create and store a new credential record on the user account
  // Also known as step 23 in https://www.w3.org/TR/webauthn-3/
  // skipped out of scope of this function
  // to be performed after calling this function

  // Step 28 - if verified but not trustworthy, fail the ceremony
  // Also known as step 24 in https://www.w3.org/TR/webauthn-3/
  // skipped N/A

  return {
    credentialId: authenticatorData.attestedCredentialData.credentialId,
    coseKey: authenticatorData.attestedCredentialData.credentialPublicKeyBytes,
    extensions: authenticatorData.extensions,
    multiDevice: authenticatorData.backupEligibility,
    backupState: authenticatorData.backupState,
    userVerified: authenticatorData.userVerified,
    signCount: authenticatorData.signCount,
    clientDataJSON: new Uint8Array(options.attestationResponse.clientDataJSON),
    attestationObject: new Uint8Array(
      options.attestationResponse.attestationObject,
    ),
  };
}
