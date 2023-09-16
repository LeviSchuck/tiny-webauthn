import { AuthenticatorTransport } from "../../index.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/deps.ts";
import { Credential, CredentialUpdate, Session, User } from "./data.ts";
import { InMemoryData } from "./inMemory.ts";

type SavedCredential = {
  id: string;
  userId: string;
  key: string;
  count: number;
  verified: boolean;
  transports?: AuthenticatorTransport[];
};

export class JsonData extends InMemoryData {
  private loaded = false;
  private loading = false;
  private path: string;
  private sessionPath: string;

  constructor(path: string, sessionPath: string) {
    super();
    this.path = path;
    this.sessionPath = sessionPath;
  }

  private async firstLoad() {
    if (!this.loaded && !this.loading) {
      this.loading = true;
      let exists = false;
      // Main path
      try {
        if (await Deno.stat(this.path)) {
          exists = true;
        }
      } catch (_e) {
        // Nothing
      }
      if (exists) {
        const text = await Deno.readTextFile(this.path);
        const json = await JSON.parse(text);
        for (const user of json.users) {
          await super.createUser({
            userId: decodeBase64Url(user.id),
            username: user.name,
          });
        }
        for (const credential of json.credentials) {
          await super.createCredential({
            userId: decodeBase64Url(credential.userId),
            credentialId: decodeBase64Url(credential.id),
            publicKey: decodeBase64Url(credential.key),
            signCount: credential.count,
            userVerified: credential.verified,
            transports: credential.transports,
          });
        }
      }
      // session path
      exists = false;
      try {
        if (await Deno.stat(this.sessionPath)) {
          exists = true;
        }
      } catch (_e) {
        // Nothing
      }

      if (exists) {
        const text = await Deno.readTextFile(this.sessionPath);
        const json = await JSON.parse(text);
        for (const session of json.sessions) {
          console.log("importing session");
          await super.createSession({
            sessionId: session.id,
            userId: decodeBase64Url(session.userId),
          });
        }
      }
      this.loaded = true;
      console.log("loaded=true");
    }
  }

  private async save() {
    const json: {
      users: {
        id: string;
        name: string;
      }[];
      credentials: SavedCredential[];
    } = {
      users: [],
      credentials: [],
    };

    for (const user of this.users.values()) {
      json.users.push({
        id: encodeBase64Url(user.userId),
        name: user.username,
      });
    }

    json.users.sort((a, b) => {
      return a.id < b.id ? -1 : 1;
    });

    for (const credential of this.credentials.values()) {
      const output: SavedCredential = {
        id: encodeBase64Url(credential.credentialId),
        userId: encodeBase64Url(credential.userId),
        key: encodeBase64Url(credential.publicKey),
        count: credential.signCount,
        verified: credential.userVerified,
      };
      if (credential.transports) {
        output.transports = credential.transports;
      }
      json.credentials.push(output);
    }

    json.credentials.sort((a, b) => {
      return a.id < b.id ? -1 : 1;
    });

    await Deno.writeTextFile(this.path, JSON.stringify(json, undefined, "  "));
  }

  private async saveSessions() {
    const json: {
      sessions: {
        id: string;
        userId: string;
      }[];
    } = { sessions: [] };
    for (const session of this.sessions.values()) {
      json.sessions.push({
        id: session.sessionId,
        userId: encodeBase64Url(session.userId),
      });
    }

    json.sessions.sort((a, b) => {
      return a.id < b.id ? -1 : 1;
    });
    await Deno.writeTextFile(
      this.sessionPath,
      JSON.stringify(json, undefined, "  "),
    );
  }

  async findUserByUserId(userId: Uint8Array): Promise<User | null> {
    await this.firstLoad();
    return await super.findUserByUserId(userId);
  }
  async findUserByUsername(username: string): Promise<User | null> {
    await this.firstLoad();
    return await super.findUserByUsername(username);
  }
  async createUser(user: User): Promise<void> {
    await super.createUser(user);
    await this.save();
  }
  async createCredential(credential: Credential): Promise<void> {
    await super.createCredential(credential);
    await this.save();
  }
  async findCredentialsForUserId(userId: Uint8Array): Promise<Credential[]> {
    await this.firstLoad();
    return await super.findCredentialsForUserId(userId);
  }
  async deleteCredential(credentialId: Uint8Array): Promise<void> {
    await super.deleteCredential(credentialId);
    await this.save();
  }
  async findCredentialById(
    credentialId: Uint8Array,
  ): Promise<Credential | null> {
    await this.firstLoad();
    return await super.findCredentialById(credentialId);
  }

  async updateCredential(
    credentialId: Uint8Array,
    update: CredentialUpdate,
  ): Promise<void> {
    await super.updateCredential(credentialId, update);
    await this.save();
  }

  async createSession(session: Session): Promise<void> {
    await super.createSession(session);
    await this.saveSessions();
  }
  async deleteSession(sessionId: string): Promise<void> {
    await super.deleteSession(sessionId);
    await this.saveSessions();
  }
  async findSession(sessionId: string): Promise<Session | null> {
    await this.firstLoad();
    return await super.findSession(sessionId);
  }
}
