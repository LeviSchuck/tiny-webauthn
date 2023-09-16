import { getCookie } from "https://deno.land/x/hono@v3.5.6/middleware.ts";
import { Context } from "https://deno.land/x/hono@v3.5.6/mod.ts";

export function getSession(c: Context): string | null {
  try {
    // Can throw errors :/
    return getCookie(c, "session") || null;
  } catch (_e) {
    // ignored
  }
  return null;
}
