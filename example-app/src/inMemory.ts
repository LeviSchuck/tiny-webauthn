import { encodeBase64Url } from "../../src/deps.ts";
import {
  Credential,
  CredentialUpdate,
  DataSource,
  Session,
  User,
} from "./data.ts";

export class InMemoryData implements DataSource {
  protected users: Map<string, User> = new Map();
  protected credentials: Map<string, Credential> = new Map();
  protected userCredentialIndex: Map<string, Set<string>> = new Map();
  protected usernameToIdIndex: Map<string, string> = new Map();
  protected sessions: Map<string, Session> = new Map();

  findUserByUserId(userId: Uint8Array): Promise<User | null> {
    const key = encodeBase64Url(userId);
    return Promise.resolve(this.users.get(key) || null);
  }
  findUserByUsername(username: string): Promise<User | null> {
    const userIdKey = this.usernameToIdIndex.get(username);
    if (!userIdKey) {
      return Promise.resolve(null);
    }
    const user = this.users.get(userIdKey) || null;
    return Promise.resolve(user);
  }
  createUser(user: User): Promise<void> {
    const key = encodeBase64Url(user.userId);
    if (this.users.has(key)) {
      throw new Error("User already exists");
    }
    if (this.usernameToIdIndex.has(user.username)) {
      throw new Error("Username conflict");
    }
    this.users.set(key, user);
    this.usernameToIdIndex.set(user.username, key);
    return Promise.resolve();
  }
  async createCredential(credential: Credential): Promise<void> {
    const key = encodeBase64Url(credential.credentialId);
    if (this.credentials.has(key)) {
      throw new Error("Credential already exists");
    }

    const user = await this.findUserByUserId(credential.userId);
    if (!user) {
      throw new Error("User does not exist");
    }

    this.credentials.set(key, credential);

    const userKey = encodeBase64Url(credential.userId);

    let credentials = this.userCredentialIndex.get(userKey);
    if (!credentials) {
      credentials = new Set();
    }
    credentials.add(key);
    this.userCredentialIndex.set(userKey, credentials);
  }
  findCredentialsForUserId(userId: Uint8Array): Promise<Credential[]> {
    const userKey = encodeBase64Url(userId);
    const credentials = this.userCredentialIndex.get(userKey);
    if (!credentials) {
      return Promise.resolve([]);
    }
    const results: Credential[] = [];
    for (const key of credentials) {
      const credential = this.credentials.get(key);
      if (credential) {
        results.push(credential);
      }
    }
    return Promise.resolve(results);
  }
  deleteCredential(credentialId: Uint8Array): Promise<void> {
    const key = encodeBase64Url(credentialId);
    const credential = this.credentials.get(key);
    if (!credential) {
      return Promise.resolve();
    }
    // unlink from user
    const userKey = encodeBase64Url(credential.userId);
    const credentials = this.userCredentialIndex.get(userKey);
    if (credentials) {
      credentials.delete(key);
      this.userCredentialIndex.set(userKey, credentials);
    }
    // Remove the credential
    this.credentials.delete(key);

    return Promise.resolve();
  }
  findCredentialById(credentialId: Uint8Array): Promise<Credential | null> {
    const key = encodeBase64Url(credentialId);
    const credential = this.credentials.get(key) || null;
    return Promise.resolve(credential);
  }

  async updateCredential(
    credentialId: Uint8Array,
    update: CredentialUpdate,
  ): Promise<void> {
    const credential = await this.findCredentialById(credentialId);
    if (!credential) {
      throw new Error("Credential not found");
    }
    if (update.signCount !== undefined) {
      credential.signCount = update.signCount;
    }
    const key = encodeBase64Url(credentialId);
    this.credentials.set(key, credential);
  }

  createSession(session: Session): Promise<void> {
    this.sessions.set(session.sessionId, session);
    return Promise.resolve();
  }
  deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    return Promise.resolve();
  }
  findSession(sessionId: string): Promise<Session | null> {
    return Promise.resolve(this.sessions.get(sessionId) || null);
  }
}
