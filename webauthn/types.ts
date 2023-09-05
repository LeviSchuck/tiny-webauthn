import { CBORType, COSEKeyAll } from "./deps.ts";
// https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions

export type COSEAlgorithmIdentifier = -7 | -257 | -8;
export type UserVerificationRequirement =
  | "discouraged"
  | "preferred"
  | "required";
export type AuthenticatorTransport =
  | "usb"
  | "nfc"
  | "ble"
  | "internal";
export type PublicKeyCredentialType = "public-key";
export type AuthenticatorAttachment = "platform" | "cross-platform";
export type ResidentKeyRequirement =
  | "discouraged"
  | "preferred"
  | "required";
export type AttestationConveyancePreference =
  | "none"
  | "indirect"
  | "direct"
  | "enterprise";
export type AttestationStatementFormat =
  | "packed"
  | "tpm"
  | "android-key"
  | "android-safetynet"
  | "fido-u2f"
  | "apple"
  | "none";
export type PublicKeyCredentialHint =
  | "security-key"
  | "client-device"
  | "hybrid";

export interface PublicKeyCredentialEntity {
  name: string;
}
export interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
  id?: string;
}
export interface PublicKeyCredentialUserEntity
  extends PublicKeyCredentialEntity {
  id: Uint8Array;
  displayName: string;
}

export interface PublicKeyCredentialParameters {
  type: PublicKeyCredentialType;
  alg: COSEAlgorithmIdentifier;
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  residentKey?: string;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirement;
}
export interface PublicKeyCredentialDescriptor {
  type: PublicKeyCredentialType;
  id: Uint8Array;
  transports?: AuthenticatorTransport[];
}
export interface PublicKeyCredentialCreationOptions {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  challenge: Uint8Array;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  // https://www.iana.org/assignments/webauthn/webauthn.xhtml#table-webauthn-extension-ids
  extensions?: object;
}
export interface AuthenticatorResponse {
  readonly clientDataJSON: ArrayBuffer;
}
export interface AuthenticatorAttestationResponse
  extends AuthenticatorResponse {
  attestationObject: ArrayBuffer;
}

export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  attestationObject?: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  clientDataJSON: ArrayBuffer;
  userHandle?: ArrayBuffer;
}

export interface AttestedCredentialData {
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  credentialPublicKey: COSEKeyAll;
  credentialPublicKeyBytes: Uint8Array;
}

export interface AuthenticatorData {
  rpIdHash: Uint8Array;
  // Begin Flags
  extensionDataIncluded: boolean; // 7
  attestedCredentialDataIncluded: boolean; // 6
  backupState: boolean; // 4
  backupEligibility: boolean; // 3
  userVerified: boolean; // 2
  userPresent: boolean; // 0
  // End of Flags
  signCount: number;
  attestedCredentialData?: AttestedCredentialData;
  extensions?: CBORType;
}

export interface CreateAuthenticatorResponse {
  fmt: CBORType;
  attStmt: CBORType;
  authData: AuthenticatorData;
  authDataBytes: Uint8Array;
}

// The working draft has a lot more options than the published
// specification.
// https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options
// https://w3c.github.io/webauthn/#dictionary-assertion-options
// https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#web_authentication_api
export interface PublicKeyCredentialRequestOptions {
  challenge: Uint8Array;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: UserVerificationRequirement;
  // Working draft only
  hints?: PublicKeyCredentialHint[];
  // Working draft only
  attestation?: AttestationConveyancePreference;
  // Working draft only
  attestationFormats?: AttestationStatementFormat[];
  // https://www.iana.org/assignments/webauthn/webauthn.xhtml#table-webauthn-extension-ids
  extensions?: object;
}
export interface Credential {
  readonly id: string;
  readonly type: string;
}
export interface PublicKeyCredential<resp extends AuthenticatorResponse>
  extends Credential {
  readonly type: "public-key";
  readonly rawId: ArrayBuffer;
  readonly response: resp;
  readonly authenticatorAttachment: AuthenticatorAttachment;
}
