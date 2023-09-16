import { Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";
import {
  serveStatic,
  setCookie,
} from "https://deno.land/x/hono@v3.5.6/middleware.ts";

import { timingSafeEqual } from "../../src/timingSafeEqual.ts";
import { serve } from "./server.ts";
import {
  homePageLoggedIn,
  homePageNotLoggedIn,
  registerPage,
  signInPage,
} from "./pages.tsx";
import { deriveCSRFToken } from "./secret.ts";
import { AppEnv } from "./env.ts";
import { authenticationApp } from "./authentication.ts";
import { registrationApp } from "./registration.ts";
import { getSession } from "./session.ts";

const ENCODER = new TextEncoder();

const app = new Hono<AppEnv>();

app.use(
  "/static/*",
  serveStatic({
    root: "./",
  }),
);

app.route("/authentication", authenticationApp);
app.route("/registration", registrationApp);

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
  await c.env.DATA_SOURCE.deleteSession(sessionId);
  return c.redirect("/", 302);
});

app.get("/", async (c) => {
  const sessionId = getSession(c);
  const session =
    (sessionId && await c.env.DATA_SOURCE.findSession(sessionId)) ||
    null;
  const user =
    (session && await c.env.DATA_SOURCE.findUserByUserId(session.userId)) ||
    null;
  if (!user || !session) {
    return homePageNotLoggedIn(c);
  }

  const csrf = await deriveCSRFToken(session.sessionId);

  const credentials = await c.env.DATA_SOURCE.findCredentialsForUserId(
    user.userId,
  );

  return homePageLoggedIn(c, csrf, user, credentials);
});
app.get("/sign-in", (c) => {
  return signInPage(c);
});
app.get("/register", (c) => {
  return registerPage(c);
});

await serve(app);
