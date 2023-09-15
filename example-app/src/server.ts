import { Hono } from "https://deno.land/x/hono@v3.5.6/mod.ts";

async function handle(app: Hono, conn: Deno.Conn) {
  const httpConn = Deno.serveHttp(conn);
  try {
    for await (const requestEvent of httpConn) {
      try {
        const begin = new Date().getTime();
        const response = await app.fetch(
          requestEvent.request,
          undefined,
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
  app: Hono,
  port: number,
  certFile: string | null,
  keyFile: string | null,
) {
  if (certFile && keyFile) {
    const server = Deno.listenTls({
      port,
      key: Deno.readTextFileSync(keyFile),
      cert: Deno.readTextFileSync(certFile),
    });

    for await (const conn of server) {
      handle(app, conn);
    }
  } else {
    const server = Deno.listen({
      port,
    });

    for await (const conn of server) {
      handle(app, conn);
    }
  }
}
