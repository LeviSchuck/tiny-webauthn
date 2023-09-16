import { timingSafeEqual } from "./timingSafeEqual.ts";
import {
  AuthenticatorAssertionResponse,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialRequestOptions,
  UserVerificationRequirement,
} from "./types.ts";
import {
  CBORType,
  decodeBase64Url,
  decodeCBOR,
  encodeBase64Url,
  importPublicKey,
  parseCBORToCOSEKey,
} from "./deps.ts";
import { parseAuthenticatorData } from "./authenticatorData.ts";
import { verifySignature } from "./verifier.ts";

export interface AuthenticationOptions {
  rpId?: string;
  userVerification?: UserVerificationRequirement;
  timeoutMillis?: number;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  // deno-lint-ignore no-explicit-any
  extensions?: any;
  challenge?: Uint8Array;
}

export interface AuthenticatingUser {
  userId: Uint8Array;
}

export interface CredentialRecord {
  userId: Uint8Array;
  credentialId: Uint8Array;
  signCount: number;
  userVerified: boolean;
  attestationObject?: Uint8Array;
  attestationClientDataJSON?: Uint8Array;
  publicKey: Uint8Array;
}

export interface AuthenticationResponse {
  credentialId: Uint8Array;
  clientExtensionResults?: object;
  allowCredentials?: Uint8Array[];
  response: AuthenticatorAssertionResponse;
  findAuthenticatingUser?(): Promise<AuthenticatingUser | null>;
  findAccountByUserId?(
    userId: Uint8Array,
  ): Promise<AuthenticatingUser | null>;
  findCredential?(credentialId: Uint8Array): Promise<CredentialRecord | null>;
  origins: string[];
  rpId: string;
  challenge: Uint8Array;
  expectedUserVerification?: true;
  updateCredential?(credentalId: Uint8Array, updates: {
    signCount?: number;
    userVerified?: boolean;
    attestationObject?: Uint8Array;
    attestationClientDataJSON?: Uint8Array;
  }): Promise<void>;
}

export interface WebAuthnAuthenticationResponse {
  credentialId: Uint8Array;
  authenticatingUser: AuthenticatingUser;
  userVerified: boolean;
  multiDevice: boolean;
  backupState: boolean;
  signCount: number;
  extensions?: CBORType;
}
interface WebAuthnGetData {
  type: "webauthn.get";
  challenge: string;
  origin: string;
  crossOrigin: boolean;
  topOrigin?: string;
}

// deno-lint-ignore require-await
export async function generateAuthenticationOptions(
  options: AuthenticationOptions,
): Promise<PublicKeyCredentialRequestOptions> {
  let challenge = crypto.getRandomValues(new Uint8Array(32));
  if (options.challenge) {
    challenge = options.challenge;
    if (challenge.length < 16) {
      throw new Error("Insufficient challenge size");
    }
  }
  const result: PublicKeyCredentialRequestOptions = {
    challenge,
  };
  if (options.rpId) {
    result.rpId = options.rpId;
  }
  result.userVerification = options.userVerification || "preferred";
  result.timeout = options.timeoutMillis || 60_000;
  if (typeof options.extensions == "object") {
    result.extensions = options.extensions;
  }
  if (options.allowCredentials) {
    for (const credential of options.allowCredentials) {
      if (credential.type != "public-key") {
        throw new Error('Expected "public-key" as type on credential');
      }
      if (!(credential.id instanceof Uint8Array)) {
        throw new Error("Expected credential id to be a Uint8Array");
      }
      if (credential.transports) {
        for (const transport of credential.transports) {
          if (
            transport != "usb" && transport != "ble" && transport != "nfc" &&
            transport != "internal"
          ) {
            throw new Error(
              `Unexpected transport "${transport}" on allowed credential`,
            );
          }
        }
      }
    }
  }
  result.allowCredentials = options.allowCredentials || [];

  return Promise.resolve(result);
}

const DECODER = new TextDecoder();
const ENCODER = new TextEncoder();

export async function verifyAuthenticationResponse(
  options: AuthenticationResponse,
): Promise<WebAuthnAuthenticationResponse> {
  // Step 1  - Create PublicKeyCredentialRequestOptions using
  //           generateAuthenticationOptions
  //           This is a server-client step, it happens outside this function
  // Step 2  - Call navigator.credentials.get
  //           This is a client step, it happens outside this function
  // Step 3  - Collect credential.response and ensure it is an
  //           AuthenticatorAssertionResponse
  //           This is a client step, it happens outside this function
  // Step 4  - collect clientExtensionResults
  //           This is a client step, it happens outside this function
  // ---------------------------------------------------------------------------
  // Step 5  - If allowCredentials is not empty, verify that the submitted
  //           credential matches the allowCredentials list
  if (options.allowCredentials && options.allowCredentials.length > 0) {
    let allowed = false;
    for (const allowedCredentialId of options.allowCredentials) {
      if (timingSafeEqual(allowedCredentialId, options.credentialId)) {
        allowed = true;
      }
    }
    if (!allowed) {
      throw new Error(
        `Credential ${
          encodeBase64Url(options.credentialId).slice(0, 12)
        }... is not allowed`,
      );
    }
  }
  // Step 6  - Find the user that is authenticating
  let authenticatingUser = (options.findAuthenticatingUser &&
    await options.findAuthenticatingUser()) || null;
  // Step 7  - If identified before the ceremony, ensure that an existing
  //           credential record exists whose ID matches the submitted
  //           credential
  const credentialRecord = (options.findCredential &&
    await options.findCredential(options.credentialId)) || null;
  if (!credentialRecord) {
    throw new Error("Credential not found");
  }
  if (
    authenticatingUser &&
    !timingSafeEqual(credentialRecord.userId, authenticatingUser.userId)
  ) {
    throw new Error("Credential does not match user");
  }
  // Step 8  - If the user was not identified, verify that the userHandle is
  //           present.
  //           Then verify that the user account matching the userHandle has a
  //           credential record with an ID that matches the submitted
  //           credential.
  if (!authenticatingUser) {
    if (!options.response.userHandle || !options.findAccountByUserId) {
      throw new Error("Could not find user");
    }
    authenticatingUser = await options.findAccountByUserId(
      new Uint8Array(options.response.userHandle),
    );
    if (!authenticatingUser) {
      throw new Error("Could not find user");
    }
    if (!timingSafeEqual(credentialRecord.userId, authenticatingUser.userId)) {
      throw new Error("Credential does not match user");
    }
  }
  // Step 9  - collect clientDataJSON, authenticatorData, and signature
  const authenticatorData = parseAuthenticatorData(
    options.response.authenticatorData,
  );
  const signature = options.response.signature;
  // Step 10 - Decode clientDataJSON from bytes to text
  // Step 11 - Decode clientDataJSON from text to JSON
  const clientDataJSON = JSON.parse(
    DECODER.decode(options.response.clientDataJSON),
  ) as WebAuthnGetData;
  // Step 12 - Verify that clientDataJSON.type is webauthn.get
  if (clientDataJSON.type != "webauthn.get") {
    throw new Error("Unexpected webauthn client json type");
  }
  // Step 13 - Verify that clientDataJSON.challenge matches the requested
  //           challenge
  if (
    !timingSafeEqual(
      options.challenge,
      decodeBase64Url(clientDataJSON.challenge),
    )
  ) {
    throw new Error("Challenge does not match");
  }
  // Step 14 - Verify that clientDataJSON.origin is the expected origin
  if (options.origins.length == 0) {
    throw new Error("Expected an origin from the verification function");
  }
  let originMatched = false;
  const encodedClientOrigin = ENCODER.encode(clientDataJSON.origin);
  for (const origin of options.origins) {
    if (origin.length == clientDataJSON.origin.length) {
      originMatched = timingSafeEqual(
        ENCODER.encode(origin),
        encodedClientOrigin,
      );
    }
    if (originMatched) {
      break;
    }
  }
  if (!originMatched) {
    throw new Error(
      `Expected origin to be one of "${
        JSON.stringify(options.origins)
      }", but was "${clientDataJSON.origin}"`,
    );
  }
  // Step 15 - Handle topOrigin - Not implemented so error if found
  if (clientDataJSON.topOrigin) {
    throw new Error("topOrigin is not supported");
  }
  // Step 16 - Verify that the rpIdHash in authData is the SHA-256 matching
  //           hash(expected rpId)
  const expectedRpIdHash = await crypto.subtle.digest(
    { name: "SHA-256" },
    ENCODER.encode(options.rpId),
  );
  if (!timingSafeEqual(expectedRpIdHash, authenticatorData.rpIdHash)) {
    throw new Error("Relying Party ID mismatch");
  }
  // Step 17 - Verify that the user was present with the userPresent flag
  if (!authenticatorData.userPresent) {
    throw new Error("Expected user presence");
  }
  // Step 18 - If user verification is expected, then verify the
  //           userVerification flag is true
  if (options.expectedUserVerification && !authenticatorData.userVerified) {
    throw new Error("Expected user verified");
  }
  // Step 19 - If backupEligible flag is false, ensure backupState is false
  if (!authenticatorData.backupEligibility && authenticatorData.backupState) {
    throw new Error(
      "Backup eligibility and state are not expected to be false and true respectively.",
    );
  }
  // Step 20 - If backupState is used for any reason, handle it here.
  //           Also, if the credential record has backupEligible true,
  //           then verify backupEligible on the credential is true.
  //           Also, if the credential record has backupEligible false,
  //           then verify that backupEligible on the credential is false.
  //           Skipping due to complexity at this time

  // Step 21 - Verify client extension outputs are as expected
  //           Skipping

  // Step 22 - hash is SHA256(clientDataJSON)
  const hash = await crypto.subtle.digest(
    { name: "SHA-256" },
    options.response.clientDataJSON,
  );
  // Step 23 - Load the publicKey from the credential record,
  //           dataToSign = authData || hash
  //           Verify the signature with the publicKey against dataToSign
  const pubKeyCbor = decodeCBOR(credentialRecord.publicKey);
  const coseKey = parseCBORToCOSEKey(pubKeyCbor);
  const { key } = await importPublicKey(coseKey);
  const dataToVerify = new Uint8Array(
    options.response.authenticatorData.byteLength + hash.byteLength,
  );
  dataToVerify.set(new Uint8Array(options.response.authenticatorData), 0);
  dataToVerify.set(
    new Uint8Array(hash),
    options.response.authenticatorData.byteLength,
  );
  if (
    !await verifySignature(
      coseKey.alg,
      key,
      new Uint8Array(signature),
      dataToVerify,
    )
  ) {
    throw new Error("Signature failed");
  }
  // Step 24 - If signCount is > 0 or credentialRecord.signCount > 0 then
  //           If signCount > credentialRecord.signCount then it is valid
  //           If signCount <= credentialRecord.signCount then it may be cloned.
  //           In this case, then do something specific here, like erroring out.
  //           Skipping due to complexity at this time
  // Step 25 - If there is an attestationObject and the RP wants to verify the
  //           attestation, then decode the attestationObject similar to
  //           registration
  //           1. Verify that attested credential data is included
  //           2. Verify the credentialRecord publicKey and id match the
  //              attested public key and credential id
  //           3. Match the fmt field to determine attestation format
  //           4. Using attestation specific verification, verify the
  //              attestation signature
  //           5. Find the relevant trust anchors
  //           Skipping due to complexity at this time
  // Step 26 - Update the credential record
  //           1. Update signCount
  //           2. Update the backupState
  //           3. If user verification on the credential record is false, update
  //              it to the credential's userVerified flag
  //              Note this should require another factor step in the
  //              overall application
  //           4. If there is an attestationObject, update the
  //              credentialRecord's attestationObject and also record the
  //              clientDataJson attached to the attestation.
  //           Skipping due to complexity at this time
  // Step 27 - If everything is good, continue (a non step)
  return {
    credentialId: credentialRecord.credentialId,
    authenticatingUser,
    userVerified: authenticatorData.userVerified,
    multiDevice: authenticatorData.backupEligibility,
    backupState: authenticatorData.backupState,
    signCount: authenticatorData.signCount,
    extensions: authenticatorData.extensions,
  };
}
