import { Context, Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";
import {
  getCookie,
  serveStatic,
  setCookie,
} from "https://deno.land/x/hono@v3.5.6/middleware.ts";

import {
  AuthenticatorAssertionResponse,
  AuthenticatorAttestationResponse,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  parseWebAuthnObject,
  stringifyWebAuthnObject,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  WebAuthnAuthenticationResponse,
  WebAuthnCreateResponse,
} from "../../index.ts";
import {
  decodeBase64Url,
  encodeBase64Url,
} from "https://deno.land/x/tiny_encodings@0.2.1/encoding.ts";
import { timingSafeEqual } from "../../src/timingSafeEqual.ts";
import { DataSource } from "./data.ts";
import { JsonData } from "./jsonData.ts";
import { serve } from "./server.ts";
import {
  assembleChallenge,
  disassembleAndVerifyChallenge,
} from "./challenge.ts";
import {
  homePageLoggedIn,
  homePageNotLoggedIn,
  registerPage,
  signInPage,
} from "./pages.tsx";

const jsonConfigFile = Deno.args[0];
if (!jsonConfigFile) {
  throw new Error(
    "Please add a JSON configuration file (like localhost.json) as the first argument",
  );
}
const jsonConfig = JSON.parse(Deno.readTextFileSync(Deno.args[0]));

const RP_ID = jsonConfig.rpId || "localhost";
const PORT = jsonConfig.port || 8000;
const ORIGINS = jsonConfig.origins || ["https://localhost:8000"];
const SECRET = jsonConfig.secret ||
  "FGRx6U2D1Pqll0hyADDyZVUA5q1goWdmpgh_T2CVGho";
const HTTPS_KEY = jsonConfig.keyFile || null;
const HTTPS_CERT = jsonConfig.certFile || null;

// This is an example app, do not use this secret
const SECRET_KEY = await crypto.subtle.importKey(
  "raw",
  decodeBase64Url(SECRET),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"],
);

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

await Deno.mkdir("../scratch", { recursive: true });
const DATA_SOURCE: DataSource = new JsonData(
  "../scratch/data.json",
  "../scratch/sessions.json",
);

async function usernameToId(username: string): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    SECRET_KEY,
    ENCODER.encode(`username:${username}`),
  );
  return new Uint8Array(signature.slice(0, 12));
}

async function deriveCSRFToken(sessionId: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    SECRET_KEY,
    ENCODER.encode(`csrf:${sessionId}`),
  );
  return encodeBase64Url(new Uint8Array(signature.slice(0, 12)));
}

const app = new Hono();

app.use(
  "/static/*",
  serveStatic({
    root: "./",
  }),
);

app.post("/find-id", async (c) => {
  const username = c.req.query("username");
  if (!username) {
    return c.json({
      error: true,
      message: "Missing username",
    }, 400);
  }
  const id = await usernameToId(username);
  return c.json({
    username,
    id,
  });
});

app.post("/registration-options", async (c) => {
  const username = c.req.query("username");
  if (!username) {
    return c.json({
      error: true,
      message: "Missing username",
    }, 400);
  }
  const passkey = c.req.query("passkey");

  const id = await usernameToId(username);
  const expiration = new Date().getTime() + 60_000;
  const random = crypto.getRandomValues(new Uint8Array(16));
  const challenge = await assembleChallenge(SECRET_KEY, random, expiration, id);

  const options = await generateRegistrationOptions({
    rpId: RP_ID,
    rpName: "example-app",
    userDisplayName: username,
    userId: id,
    userName: username,
    timeoutMilliseconds: 120_000,
    challenge,
    kind: passkey && "passkey" || "server-side",
    supportedAlgorithms: [-8, -7, -257],
  });

  const json = {
    options: stringifyWebAuthnObject(options),
    authenticatingData: {
      challenge: encodeBase64Url(challenge),
      expiration,
      userId: encodeBase64Url(id),
    },
  };
  console.log(json.options);
  return c.json(json);
});

app.post("/register", async (c) => {
  const body = await c.req.json() as {
    username: string;
    response: string;
  };
  const response = parseWebAuthnObject(
    body.response,
  ) as AuthenticatorAttestationResponse;
  if (!(response as AuthenticatorAttestationResponse).attestationObject) {
    return c.json({
      error: true,
      message: "Missing attestationObject",
    }, 400);
  }

  const clientDataJson = JSON.parse(
    DECODER.decode(response.clientDataJSON),
  ) as { challenge: string };
  const challenge = decodeBase64Url(clientDataJson.challenge);

  let userId: Uint8Array;
  try {
    const result = await disassembleAndVerifyChallenge(SECRET_KEY, challenge);
    userId = result.userId;
    const expiration = result.expiration;
    if (new Date().getTime() > expiration) {
      return c.json({
        error: true,
        message: "Challenge expired",
      }, 400);
    }
    const expectedUserId = await usernameToId(body.username);
    if (!timingSafeEqual(userId, expectedUserId)) {
      console.log(`Expected`, expectedUserId, `got`, userId);
      return c.json({
        error: true,
        message: "User ID did not match the challenge",
      }, 400);
    }
  } catch (e) {
    return c.json({
      error: true,
      message: (e as Error).message,
    }, 400);
  }
  // TODO see if userID has been registered yet
  const existingUser = await DATA_SOURCE.findUserByUserId(userId);
  if (existingUser) {
    return c.json({
      error: true,
      message: "User already registered",
    }, 400);
  }

  let verification: WebAuthnCreateResponse;
  try {
    verification = await verifyRegistrationResponse({
      rpId: RP_ID,
      origin: ORIGINS,
      attestationResponse: response as AuthenticatorAttestationResponse,
      challenge,
      expectedAlgorithms: [-8, -7, -257],
    });
  } catch (e) {
    console.error(e);
    return c.json({
      error: true,
      message: "verification failed",
    }, 400);
  }

  await DATA_SOURCE.createUser({
    userId,
    username: body.username,
  });
  console.log("# Registration");
  console.log("#" + "-".repeat(79));
  console.log(`username: ${body.username}`);
  console.log(`userId: ${encodeBase64Url(userId)}`);
  console.log(`challenge: ${encodeBase64Url(challenge)}`);
  console.log(`clientDataJson: ${encodeBase64Url(response.clientDataJSON)}`);
  console.log(
    `attestationObject: ${encodeBase64Url(response.attestationObject)}`,
  );
  console.log(`credentialId: ${encodeBase64Url(verification.credentialId)}`);
  console.log(`publicKey: ${encodeBase64Url(verification.coseKey)}`);
  console.log(`signCount: ${verification.signCount}`);
  console.log("#" + "-".repeat(79));

  await DATA_SOURCE.createCredential({
    credentialId: verification.credentialId,
    publicKey: verification.coseKey,
    signCount: verification.signCount,
    userId: userId,
    userVerified: verification.userVerified,
  });

  const sessionId = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  await DATA_SOURCE.createSession({
    sessionId,
    userId,
  });

  setCookie(c, "session", sessionId, {
    httpOnly: true,
    secure: true,
  });
  return c.json({
    status: "OK",
  });
});

app.post("/authentication", async (c) => {
  const body = await c.req.json() as {
    username: string;
    response: string;
    credentialId: string;
  };
  const response = parseWebAuthnObject(
    body.response,
  ) as AuthenticatorAssertionResponse;
  if (!(response as AuthenticatorAssertionResponse).signature) {
    return c.json({
      error: true,
      message: "Missing signature",
    }, 400);
  }
  const clientDataJson = JSON.parse(
    DECODER.decode(response.clientDataJSON),
  ) as { challenge: string };
  const challenge = decodeBase64Url(clientDataJson.challenge);
  let userId: Uint8Array;
  try {
    const result = await disassembleAndVerifyChallenge(SECRET_KEY, challenge);
    userId = result.userId;
    const expiration = result.expiration;
    if (new Date().getTime() > expiration) {
      return c.json({
        error: true,
        message: "Challenge expired",
      }, 400);
    }
    const expectedUserId = await usernameToId(body.username);
    if (!timingSafeEqual(userId, expectedUserId)) {
      console.log(`Expected`, expectedUserId, `got`, userId);
      return c.json({
        error: true,
        message: "User ID did not match the challenge",
      }, 400);
    }
  } catch (e) {
    return c.json({
      error: true,
      message: (e as Error).message,
    }, 400);
  }

  // The user must exist
  const existingUser = await DATA_SOURCE.findUserByUserId(userId);
  if (!existingUser) {
    return c.json({
      error: true,
      message: "verification failed",
    }, 400);
  }

  let verification: WebAuthnAuthenticationResponse;
  try {
    verification = await verifyAuthenticationResponse({
      rpId: RP_ID,
      origin: ORIGINS,
      challenge,
      credentialId: decodeBase64Url(body.credentialId),
      response: response,
      findAuthenticatingUser() {
        return Promise.resolve({
          userId: existingUser.userId,
        });
      },
      async findCredential(credentialId: Uint8Array) {
        const credential = await DATA_SOURCE.findCredentialById(credentialId);
        if (!credential) {
          return null;
        }
        return {
          credentialId: credential.credentialId,
          publicKey: credential.publicKey,
          signCount: credential.signCount,
          userVerified: credential.userVerified,
          userId: credential.userId,
        };
      },
      async updateCredential(credentalId, updates) {
        await DATA_SOURCE.updateCredential(credentalId, {
          signCount: updates.signCount,
        });
      },
    });
  } catch (e) {
    console.error(e);
    return c.json({
      error: true,
      message: "verification failed",
    }, 400);
  }

  const sessionId = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  await DATA_SOURCE.createSession({
    sessionId,
    userId,
  });

  console.log("# Authentication");
  console.log("#" + "-".repeat(79));
  console.log(`userId: ${encodeBase64Url(userId)}`);
  console.log(`challenge: ${encodeBase64Url(challenge)}`);
  console.log(`clientDataJson: ${encodeBase64Url(response.clientDataJSON)}`);
  console.log(`signature: ${encodeBase64Url(response.signature)}`);
  console.log(
    `authenticatorData: ${encodeBase64Url(response.authenticatorData)}`,
  );
  console.log(
    `attestationObject: ${
      response.attestationObject && encodeBase64Url(response.attestationObject)
    }`,
  );
  console.log(`credentialId: ${encodeBase64Url(verification.credentialId)}`);
  console.log(`multiDevice: ${verification.multiDevice}`);
  console.log(`signCount: ${verification.signCount}`);
  console.log(`userVerified: ${verification.userVerified}`);
  console.log("#" + "-".repeat(79));

  setCookie(c, "session", sessionId, {
    httpOnly: true,
    secure: true,
  });
  return c.json({
    status: "OK",
  });
});

app.post("/authentication-options", async (c) => {
  const username = c.req.query("username");
  if (!username) {
    return c.json({
      error: true,
      message: "Missing username",
    }, 400);
  }
  const user = await DATA_SOURCE.findUserByUsername(username);
  if (!user) {
    return c.json({
      credentials: [],
    });
  }

  const credentials = await DATA_SOURCE.findCredentialsForUserId(user.userId);

  const id = await usernameToId(username);
  const expiration = new Date().getTime() + 10_000;
  const random = crypto.getRandomValues(new Uint8Array(16));
  const challenge = await assembleChallenge(SECRET_KEY, random, expiration, id);

  const options = await generateAuthenticationOptions({
    allowCredentials: credentials.map((c) => ({
      type: "public-key",
      id: c.credentialId,
    })),
    rpId: RP_ID,
    challenge,
  });

  console.log(`options challenge`, challenge);

  return c.json({
    options: stringifyWebAuthnObject(options),
  });
});

function getSession(c: Context): string | null {
  try {
    // Can throw errors :/
    return getCookie(c, "session") || null;
  } catch (_e) {
    // ignored
  }
  return null;
}

app.post("/sign-out", async (c) => {
  const sessionId = getSession(c);
  if (!sessionId) {
    return c.redirect("/", 302);
  }
  const expectedCSRF = await deriveCSRFToken(sessionId);
  const form = await c.req.formData();
  const csrf = form.get("csrf");
  if (!csrf || typeof csrf != "string") {
    return c.text("Missing CSRF", 400);
  }
  if (!timingSafeEqual(ENCODER.encode(expectedCSRF), ENCODER.encode(csrf))) {
    return c.text("Bad CSRF", 400);
  }
  setCookie(c, "session", "", {
    expires: new Date(new Date().getTime() - 1000),
    httpOnly: true,
    secure: true,
  });
  await DATA_SOURCE.deleteSession(sessionId);
  return c.redirect("/", 302);
});

app.get("/", async (c) => {
  const sessionId = getSession(c);
  const session = (sessionId && await DATA_SOURCE.findSession(sessionId)) ||
    null;
  const user =
    (session && await DATA_SOURCE.findUserByUserId(session.userId)) || null;
  if (!user || !session) {
    return homePageNotLoggedIn(c);
  }

  const csrf = await deriveCSRFToken(session.sessionId);
  return homePageLoggedIn(c, csrf, user);
});
app.get("/sign-in", (c) => {
  return signInPage(c);
});
app.get("/register", (c) => {
  return registerPage(c);
});

await serve(app, PORT, HTTPS_CERT, HTTPS_KEY);
