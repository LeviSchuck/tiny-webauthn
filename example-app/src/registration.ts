import { Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";
import { AppEnv } from "./env.ts";
import {
  parseWebAuthnObject,
  stringifyWebAuthnObject,
} from "../../src/helper.ts";
import { decodeBase64Url, encodeBase64Url } from "../../src/deps.ts";
import {
  assembleChallenge,
  disassembleAndVerifyChallenge,
} from "./challenge.ts";
import { usernameToId } from "./secret.ts";
import { timingSafeEqual } from "../../src/timingSafeEqual.ts";
import { setCookie } from "https://deno.land/x/hono@v3.5.6/middleware.ts";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "../../src/register.ts";
import {
  AuthenticatorAttestationResponse,
  AuthenticatorTransport,
  WebAuthnCreateResponse,
} from "../../index.ts";

export const registrationApp = new Hono<AppEnv>();

const DECODER = new TextDecoder();

registrationApp.post("/options", async (c) => {
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
  const challenge = await assembleChallenge(random, expiration, id);

  const options = await generateRegistrationOptions({
    rpId: c.env.RP_ID,
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

registrationApp.post("/submit", async (c) => {
  const body = await c.req.json() as {
    username: string;
    response: string;
    transports?: AuthenticatorTransport[];
  };

  if (body.transports) {
    for (const transport of body.transports) {
      if (
        transport != "ble" && transport != "hybrid" &&
        transport != "internal" && transport != "nfc" &&
        transport != "smart-card" && transport != "usb"
      ) {
        return c.json({
          error: true,
          message: `Unexpected transport "${transport}"`,
        }, 400);
      }
    }
  }

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
  // TODO see if userID has been registered yet
  const existingUser = await c.env.DATA_SOURCE.findUserByUserId(userId);
  if (existingUser) {
    return c.json({
      error: true,
      message: "User already registered",
    }, 400);
  }

  let verification: WebAuthnCreateResponse;
  try {
    verification = await verifyRegistrationResponse({
      rpId: c.env.RP_ID,
      origins: c.env.ORIGINS,
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

  const transports = body.transports;

  // TODO

  await c.env.DATA_SOURCE.createUser({
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
  console.log(`transports: ${transports && JSON.stringify(transports)}`);
  console.log("#" + "-".repeat(79));

  await c.env.DATA_SOURCE.createCredential({
    credentialId: verification.credentialId,
    publicKey: verification.coseKey,
    signCount: verification.signCount,
    userId: userId,
    userVerified: verification.userVerified,
    transports,
  });

  const sessionId = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  await c.env.DATA_SOURCE.createSession({
    sessionId,
    userId,
  });

  setCookie(c, "session", sessionId, {
    httpOnly: true,
    secure: c.env.RP_ID != "localhost",
    path: "/",
  });
  return c.json({
    status: "OK",
  });
});
