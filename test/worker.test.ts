/**
 * The Worker skeleton, exercised against a real miniflare D1 binding and
 * against stubs that make the storage probe fail.
 *
 * The proxy is opened the way test/helpers/d1.ts opens it — same config file,
 * `persist: false`, disposed in `afterAll` — but without applying migrations:
 * the health probe has to answer on an empty database.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getPlatformProxy } from "wrangler";
import handler, { handleRequest } from "../src/worker/index.js";
import type { Env } from "../src/worker/env.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { CONFIG_PATH } from "./helpers/d1.js";

/** A D1Like whose `first()` behaves however the test needs it to. */
function stubDatabase(first: () => Promise<unknown>): D1Like {
  const statement = {
    bind: () => statement,
    first,
    all: () => Promise.reject(new Error("not used")),
    run: () => Promise.reject(new Error("not used")),
  } as unknown as D1LikeStatement;
  return {
    prepare: () => statement,
    batch: () => Promise.reject(new Error("not used")),
    exec: () => Promise.reject(new Error("not used")),
  } as unknown as D1Like;
}

describe("worker against a real D1 binding", () => {
  let env: Env;
  let dispose: () => Promise<void>;

  beforeAll(async () => {
    const platform = await getPlatformProxy<Env>({
      configPath: CONFIG_PATH,
      persist: false,
    });
    env = platform.env;
    dispose = () => platform.dispose();
  });

  afterAll(async () => {
    await dispose();
  });

  it("reads ENVIRONMENT from wrangler.jsonc, not from src", () => {
    // The top-level (local) environment of the config file.
    expect(env.ENVIRONMENT).toBe("local");
  });

  it("reads the maintainer agent id from wrangler.jsonc too", () => {
    // A var, not a secret: it is a public key, and the naming power it carries
    // is one the public has to be able to check the holder of (D-016).
    expect(env.MAINTAINER_AGENT_ID).toMatch(/^1F916:[A-Za-z0-9_-]+$/);
  });

  it("answers GET /health with 200 and a healthy body", async () => {
    const response = await handleRequest(
      new Request("https://nomankind.ai/health"),
      env,
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");

    const body = await response.json();
    expect(body).toEqual({ ok: true, environment: "local", storage: "ok" });
    // The environment is echoed from the binding, not written down in src.
    expect((body as { environment: string }).environment).toBe(env.ENVIRONMENT);
  });

  it("rejects POST /health with 405 and an Allow header", async () => {
    const response = await handleRequest(
      new Request("https://nomankind.ai/health", { method: "POST" }),
      env,
    );

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      ok: false,
      error: "method_not_allowed",
    });
  });

  it("answers an unknown path with 404", async () => {
    const response = await handleRequest(new Request("https://nomankind.ai/nope"), env);

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ ok: false, error: "not_found" });
  });

  it("exports a fetch that routes the way handleRequest does", async () => {
    // Not the same function object any more: the deployed entry point passes no
    // deps, so no argument a request carries can swap the clock or an adapter.
    const response = await handler.fetch(
      new Request("https://nomankind.ai/health"),
      env,
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      environment: "local",
      storage: "ok",
    });
  });
});

/** A D1Like where every call into the database fails, however it is reached. */
function unreachableDatabase(): D1Like {
  const fail = (): Promise<never> =>
    Promise.reject(new Error("D1_ERROR: no such table: operators"));
  const statement = {
    bind: () => statement,
    first: fail,
    all: fail,
    run: fail,
  } as unknown as D1LikeStatement;
  return {
    prepare: () => statement,
    batch: fail,
    exec: fail,
  } as unknown as D1Like;
}

describe("registry routes when storage is unreachable", () => {
  const env: Env = {
    DB: unreachableDatabase(),
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  };

  /** Every registry route answers the way the health probe does. */
  async function expectUnreachable(request: Request): Promise<void> {
    const response = await handleRequest(request, env);

    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ error: "storage_unreachable" });
  }

  it("answers GET /operators with 503 rather than a raw 500", async () => {
    await expectUnreachable(new Request("https://nomankind.ai/operators"));
  });

  it("answers GET /agents/{id} the same way", async () => {
    await expectUnreachable(new Request("https://nomankind.ai/agents/x"));
  });

  it("answers a write the same way, before it can even check the nonce", async () => {
    // Unsigned, so this would be a 401 on a database that answered: the nonce
    // store is D1, so the storage failure is what this request meets first.
    await expectUnreachable(
      new Request("https://nomankind.ai/operators", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    );
  });
});

describe("worker when storage is unreachable", () => {
  it("reports 503 when the probe throws", async () => {
    const env: Env = {
      DB: stubDatabase(() => Promise.reject(new Error("D1_ERROR: no such database"))),
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "",
    };

    const response = await handleRequest(
      new Request("https://nomankind.ai/health"),
      env,
    );

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      ok: false,
      environment: "local",
      storage: "unreachable",
    });
  });

  it("reports 503 when the probe returns no row", async () => {
    const env: Env = {
      DB: stubDatabase(() => Promise.resolve(null)),
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "",
    };

    const response = await handleRequest(
      new Request("https://nomankind.ai/health"),
      env,
    );

    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body).toEqual({
      ok: false,
      environment: "local",
      storage: "unreachable",
    });
  });
});
