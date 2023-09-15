/** @jsx jsx */
import { Context, Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";
import { jsx } from "https://deno.land/x/hono@v3.5.6/middleware.ts";
import { User } from "./data.ts";

export function signInPage(c: Context): Response {
  return c.html(
    <html>
      <body>
        <head>
          <link rel="stylesheet" href="/static/style.css" />
        </head>
        <div class="content">
          <h1>Sign in</h1>
          <label for="username">Username:</label>
          <input type="text" id="username" />
          <br />
          <button id="sign-in">Sign In</button>
          <div id="status"></div>
        </div>
        <script type="text/javascript" src="/static/utils.js"></script>
        <script type="text/javascript" src="/static/sign-in.js"></script>
      </body>
    </html>,
  );
}

export function homePageLoggedIn(c: Context, csrf: string, user: User) {
  return c.html(
    <html>
      <body>
        <head>
          <link rel="stylesheet" href="/static/style.css" />
        </head>
        <div class="content">
          <h1>WebAuthn Demo</h1>
          <p>You are logged in as {user.username}</p>
          <form method="post" action="/sign-out">
            <button type="submit">Sign Out</button>
            <input type="hidden" name="csrf" value={csrf} />
          </form>
        </div>
      </body>
    </html>,
  );
}

export function homePageNotLoggedIn(c: Context) {
  return c.html(
    <html>
      <body>
        <head>
          <link rel="stylesheet" href="/static/style.css" />
        </head>
        <div class="content">
          <h1>WebAuthn Demo</h1>
          <a href="/register">
            <button>Register</button>
          </a>
          <br />
          <a href="/sign-in">
            <button>Sign In with username</button>
          </a>
        </div>
      </body>
    </html>,
  );
}

export function registerPage(c: Context) {
  return c.html(
    <html>
      <body>
        <head>
          <link rel="stylesheet" href="/static/style.css" />
        </head>
        <div class="content">
          <h1>Register</h1>
          <label for="username">Username:</label>
          <input type="text" id="username" />
          <br />
          <label for="passkey">Passkey:</label>
          <input type="checkbox" id="passkey" />
          <br />
          <button id="register">Register</button>
          <div id="status"></div>
        </div>
        <script type="text/javascript" src="/static/utils.js"></script>
        <script type="text/javascript" src="/static/register.js"></script>
      </body>
    </html>,
  );
}