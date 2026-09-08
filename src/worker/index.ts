/**
 * The Worker entry point.
 *
 * Whitepaper Section 11, Deployment and status: every merge to main deploys
 * this Worker to demo and production through a public build action. This
 * milestone mounts one route, `GET /health`, whose only job is to say whether
 * the Worker booted and whether its D1 binding answers. Later milestones
 * (M12 to M19) mount the real routes — submission, entries, verification,
 * the public pages — on the same router.
 *
 * The health probe fails loud. If D1 does not answer, the endpoint reports 503
 * and `storage: "unreachable"`; it never reports `ok` on a database it could
 * not reach. It also deliberately does not go through the repository: the probe
 * has to work before any migration has run, so it asks D1 the one question that
 * needs no schema.
 *
 * No policy number lives here — nothing in this file is a policy number; the
 * bare integers are HTTP status codes. No environment-specific branch lives
 * here either: `ENVIRONMENT` is read from the binding and echoed back.
 */

import type { Env } from "./env.js";

/** Every response this Worker writes is JSON that must not be cached. */
function json(body: unknown, status: number, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set("content-type", "application/json");
  headers.set("cache-control", "no-store");
  return new Response(JSON.stringify(body), { status, headers });
}

/**
 * Ask D1 the cheapest question there is.
 *
 * Returns true only when a row actually came back: a driver that resolves with
 * nothing is as broken, for our purposes, as one that throws.
 */
async function storageReachable(env: Env): Promise<boolean> {
  try {
    const row = await env.DB.prepare("SELECT 1").first();
    return row !== null && row !== undefined;
  } catch (error) {
    // The message only: no binding contents, no request data.
    console.error(
      `health: storage probe failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return false;
  }
}

async function health(env: Env): Promise<Response> {
  const reachable = await storageReachable(env);
  if (!reachable) {
    return json(
      { ok: false, environment: env.ENVIRONMENT, storage: "unreachable" },
      503,
    );
  }
  return json({ ok: true, environment: env.ENVIRONMENT, storage: "ok" }, 200);
}

/** The router. Exported by name so tests can call it without a fetch stack. */
export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);

  if (pathname === "/health") {
    if (request.method !== "GET") {
      return json({ ok: false, error: "method_not_allowed" }, 405, { allow: "GET" });
    }
    return health(env);
  }

  return json({ ok: false, error: "not_found" }, 404);
}

export default { fetch: handleRequest };
