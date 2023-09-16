import { AuthenticatorTransport } from "../../index.ts";

export interface User {
  username: string;
  userId: Uint8Array;
}
export interface Credential {
  userId: Uint8Array;
  credentialId: Uint8Array;
  signCount: number;
  userVerified: boolean;
  publicKey: Uint8Array;
  transports?: AuthenticatorTransport[];
}
export interface CredentialUpdate {
  signCount?: number;
}
export interface Session {
  sessionId: string;
  userId: Uint8Array;
}

export interface DataSource {
  findUserByUserId(userId: Uint8Array): Promise<User | null>;
  findUserByUsername(username: string): Promise<User | null>;
  createUser(user: User): Promise<void>;
  createCredential(credential: Credential): Promise<void>;
  findCredentialsForUserId(userId: Uint8Array): Promise<Credential[]>;
  deleteCredential(credentialId: Uint8Array): Promise<void>;
  findCredentialById(credentialId: Uint8Array): Promise<Credential | null>;
  updateCredential(
    credentialId: Uint8Array,
    update: CredentialUpdate,
  ): Promise<void>;
  createSession(session: Session): Promise<void>;
  deleteSession(sessionId: string): Promise<void>;
  findSession(sessionId: string): Promise<Session | null>;
}
