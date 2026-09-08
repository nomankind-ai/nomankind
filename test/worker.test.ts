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

  it("exports the same function as default.fetch and handleRequest", () => {
    expect(handler.fetch).toBe(handleRequest);
  });
});

describe("worker when storage is unreachable", () => {
  it("reports 503 when the probe throws", async () => {
    const env: Env = {
      DB: stubDatabase(() => Promise.reject(new Error("D1_ERROR: no such database"))),
      ENVIRONMENT: "local",
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
