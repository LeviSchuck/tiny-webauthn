import { Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";
import { AppEnv } from "./env.ts";
import { AuthenticatorAssertionResponse, WebAuthnAuthenticationResponse } from "../../index.ts";
import { parseWebAuthnObject, stringifyWebAuthnObject } from "../../src/helper.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/deps.ts";
import { assembleChallenge, disassembleAndVerifyChallenge } from "./challenge.ts";
import { usernameToId } from "./secret.ts";
import { timingSafeEqual } from "../../src/timingSafeEqual.ts";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "../../src/authentication.ts";
import { setCookie } from "https://deno.land/x/hono@v3.5.6/middleware.ts";

export const authenticationApp = new Hono<AppEnv>();

const DECODER = new TextDecoder();

authenticationApp.post("/submit", async (c) => {
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
    const result = await disassembleAndVerifyChallenge(challenge);
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
  const existingUser = await c.env.DATA_SOURCE.findUserByUserId(userId);
  if (!existingUser) {
    return c.json({
      error: true,
      message: "verification failed",
    }, 400);
  }

  let verification: WebAuthnAuthenticationResponse;
  try {
    verification = await verifyAuthenticationResponse({
      rpId: c.env.RP_ID,
      origins: c.env.ORIGINS,
      challenge,
      credentialId: decodeBase64Url(body.credentialId),
      response: response,
      findAuthenticatingUser() {
        return Promise.resolve({
          userId: existingUser.userId,
        });
      },
      async findCredential(credentialId: Uint8Array) {
        const credential = await c.env.DATA_SOURCE.findCredentialById(credentialId);
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
        await c.env.DATA_SOURCE.updateCredential(credentalId, {
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
  await c.env.DATA_SOURCE.createSession({
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
    secure: c.env.RP_ID != "localhost",
    path: '/'
  });
  return c.json({
    status: "OK",
  });
});

authenticationApp.post("/options", async (c) => {
  const username = c.req.query("username");
  if (!username) {
    return c.json({
      error: true,
      message: "Missing username",
    }, 400);
  }
  const user = await c.env.DATA_SOURCE.findUserByUsername(username);
  if (!user) {
    return c.json({
      credentials: [],
    });
  }

  const credentials = await c.env.DATA_SOURCE.findCredentialsForUserId(user.userId);

  const id = await usernameToId(username);
  const expiration = new Date().getTime() + 10_000;
  const random = crypto.getRandomValues(new Uint8Array(16));
  const challenge = await assembleChallenge(random, expiration, id);

  const options = await generateAuthenticationOptions({
    allowCredentials: credentials.map((c) => ({
      type: "public-key",
      id: c.credentialId,
    })),
    rpId: c.env.RP_ID,
    challenge,
  });

  console.log(`options challenge`, challenge);

  return c.json({
    options: stringifyWebAuthnObject(options),
  });
});