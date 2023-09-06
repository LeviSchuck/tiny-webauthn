export {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "./authentication.ts";
export type {
  AuthenticatingUser,
  AuthenticationOptions,
  AuthenticationResponse,
  CredentialRecord,
  WebAuthnAuthenticationResponse,
} from "./authentication.ts";
export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "./register.ts";
export type {
  RegistrationOptions,
  RegistrationVerification,
  WebAuthnCreateResponse,
} from "./register.ts";
export type * from "./types.ts";
export { parseWebAuthnObject, stringifyWebAuthnObject } from "./helper.ts";
