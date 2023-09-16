import { Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";
import { loadSecretKey } from "./secret.ts";
import { AppEnv } from "./env.ts";
import { DataSource } from "./data.ts";
import { JsonData } from "./jsonData.ts";

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

async function handle(
  app: Hono<AppEnv>,
  conn: Deno.Conn,
  dataSource: DataSource,
) {
  const httpConn = Deno.serveHttp(conn);
  try {
    for await (const requestEvent of httpConn) {
      try {
        const begin = new Date().getTime();
        const response = await app.fetch(
          requestEvent.request,
          {
            ORIGINS: ORIGINS,
            RP_ID: RP_ID,
            DATA_SOURCE: dataSource,
          },
          undefined,
        );
        const end = new Date().getTime();
        console.log(
          `${requestEvent.request.method} ${requestEvent.request.url} ${
            end - begin
          }ms`,
        );
        await requestEvent.respondWith(response);
      } catch (error) {
        console.error(error);
      }
    }
  } catch (e) {
    console.error(e);
  } finally {
    try {
      httpConn.close();
    } catch (_e) {
      console.warn("Could not close connection");
    }
  }
}

export async function serve(
  app: Hono<AppEnv>,
) {
  await loadSecretKey(SECRET);
  await Deno.mkdir("../scratch", { recursive: true });
  const DATA_SOURCE: DataSource = new JsonData(
    "../scratch/data.json",
    "../scratch/sessions.json",
  );
  if (HTTPS_CERT && HTTPS_KEY) {
    const server = Deno.listenTls({
      port: PORT,
      key: Deno.readTextFileSync(HTTPS_KEY),
      cert: Deno.readTextFileSync(HTTPS_CERT),
    });

    for await (const conn of server) {
      handle(app, conn, DATA_SOURCE);
    }
  } else {
    const server = Deno.listen({
      port: PORT,
    });

    for await (const conn of server) {
      handle(app, conn, DATA_SOURCE);
    }
  }
}
