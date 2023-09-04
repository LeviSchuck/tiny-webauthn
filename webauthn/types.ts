import { CBORType, COSEKeyAll } from "./deps.ts";
// https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions

export type COSEAlgorithmIdentifier = -7 | -257;
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
  extensions?: object;
}

export interface AuthenticatorAttestationResponse {
  attestationObject: ArrayBuffer;
  clientDataJSON: ArrayBuffer;
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
