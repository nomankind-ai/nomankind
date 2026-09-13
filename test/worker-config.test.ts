/**
 * Configuration, read one way (the QA of 2026-09-12).
 *
 * Three things the QA found and this pins.
 *
 * An optional binding had two absent values. `MAINTAINER_AGENT_ID` unset
 * arrived as `undefined` and the doors tested it against `""`, so the genesis
 * door answered a deployment that had named no maintainer 403 `not_maintainer`
 * — "you are not the maintainer", about a maintainer nobody configured — and
 * the two doors that archive a capture sailed past their own
 * `fetcher_not_configured` and would have written a sidecar naming `undefined`
 * as the identity that fetched.
 *
 * `ENVIRONMENT` was an open string. It chooses the payout, the payment and the
 * witness adapters, and each of them picks its mock by asking whether the name
 * is `production` — so a var misspelt `prodcution` selected the mocks on what
 * was otherwise a real deployment, silently.
 *
 * And the transport header was on nothing at all.
 *
 * A real migrated D1 with nothing in it: what is checked is what the doors
 * answer about their own configuration, which no record can change. The clock
 * is injected, as everywhere else.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { STRICT_TRANSPORT_SECURITY } from "../src/ui/html.js";
import {
  ENVIRONMENTS,
  configured,
  environmentConfigured,
  maintainerAgentId,
} from "../src/worker/config.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
import { runSweep, SWEEP_STEPS } from "../src/worker/sweep.js";
import { sweepSteps } from "../src/storage/repository.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-12T00:00:00.000Z");
const ORIGIN = "https://app.nomankind.ai";

let store: TestDatabase;

beforeAll(async () => {
  store = await openTestDatabase();
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

/** An env with nothing configured but what a test names. */
function envWith(overrides: Record<string, unknown>): Env {
  return {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    ...overrides,
  } as unknown as Env;
}

function send(env: Env, path: string, method = "GET"): Promise<Response> {
  return handleRequest(
    new Request(`${ORIGIN}${path}`, {
      method,
      headers: { accept: "application/json" },
    }),
    env,
    { now: NOW },
  );
}

describe("an optional binding has one absent value and not two", () => {
  it("reads undefined and the empty string alike as absent", () => {
    expect(configured(undefined)).toBeNull();
    expect(configured("")).toBeNull();
    expect(configured("1F916:abc")).toBe("1F916:abc");
  });

  it("reads an unset maintainer the same way as an empty one", () => {
    expect(maintainerAgentId(envWith({}))).toBeNull();
    expect(maintainerAgentId(envWith({ MAINTAINER_AGENT_ID: "" }))).toBeNull();
    expect(
      maintainerAgentId(envWith({ MAINTAINER_AGENT_ID: "1F916:x" })),
    ).toBe("1F916:x");
  });

  it("answers the genesis door 503 maintainer_not_configured either way", async () => {
    for (const binding of [{}, { MAINTAINER_AGENT_ID: "" }]) {
      const response = await send(envWith(binding), "/genesis", "POST");
      // The request is unsigned, so the shape of the refusal below the
      // authentication is what matters: whichever of the two it is, it is never
      // 403 not_maintainer, which is what an unset binding used to earn.
      expect(await response.text()).not.toContain("not_maintainer");
    }
  }, 60_000);
});

describe("ENVIRONMENT is a closed set", () => {
  it("knows exactly the three names wrangler.jsonc sets", () => {
    expect([...ENVIRONMENTS]).toEqual(["local", "demo", "production"]);
    for (const name of ENVIRONMENTS) {
      expect(environmentConfigured(envWith({ ENVIRONMENT: name }))).toBe(true);
    }
    for (const name of ["", "prodcution", "Production", "staging"]) {
      expect(environmentConfigured(envWith({ ENVIRONMENT: name }))).toBe(false);
    }
  });

  it("refuses every door, health included, with the value it was given", async () => {
    const env = envWith({ ENVIRONMENT: "prodcution" });
    for (const path of [
      "/health",
      "/policy",
      "/events",
      "/seals",
      "/anchors",
      "/standing",
      "/status",
      "/operators",
      "/nothing-here",
    ]) {
      const response = await send(env, path);
      expect([path, response.status]).toEqual([path, 503]);
      expect(await response.json()).toEqual({
        ok: false,
        error: "environment_misconfigured",
        environment: "prodcution",
        storage: "unknown",
      });
    }
  }, 120_000);

  it("answers a HEAD the same way, without a body", async () => {
    const env = envWith({ ENVIRONMENT: "staging" });
    const response = await send(env, "/health", "HEAD");
    expect(response.status).toBe(503);
    expect(await response.text()).toBe("");
  }, 60_000);

  it("sweeps nothing and records the reason on every step", async () => {
    const env = envWith({ ENVIRONMENT: "prodcution" });
    // A beacon that throws if it is read: a misconfigured run must not reach
    // the chain, or anything else outside this process.
    const report = await runSweep(env, {
      now: NOW,
      beacon: {
        latest: () => {
          throw new Error("the sweep must not read the beacon");
        },
      } as never,
    });

    expect(report.sealed).toBeNull();
    expect(report.snapshot).toBeNull();
    expect(report.drawn).toEqual([]);
    expect(report.staled).toEqual([]);
    expect(report.skipped).toEqual({
      environment_misconfigured: SWEEP_STEPS.length,
    });

    // Every step, the run's own row included, carries the reason, and because
    // the run's row carries it too the board marks each of them `threw:` — the
    // prefix src/status.ts reads as "this stage did not get through, and here
    // is why". That is the right light for a deployment that cannot sweep:
    // failing, with the reason on the line, rather than idle and silent.
    const rows = await sweepSteps(store.db);
    expect(rows.length).toBe(SWEEP_STEPS.length);
    for (const row of rows) {
      expect([row.step, row.last_skip_reason, row.last_ok_at]).toEqual([
        row.step,
        "threw: environment_misconfigured",
        null,
      ]);
    }
  }, 120_000);
});

describe("strict-transport-security", () => {
  const env = () => envWith({});

  it("is a year, this host alone, with no preload", () => {
    expect(STRICT_TRANSPORT_SECURITY).toBe("max-age=31536000");
    expect(STRICT_TRANSPORT_SECURITY).not.toContain("includeSubDomains");
    expect(STRICT_TRANSPORT_SECURITY).not.toContain("preload");
  });

  it("is on a JSON answer, a refusal and a page alike", async () => {
    const ok = await send(env(), "/policy");
    expect(ok.status).toBe(200);
    expect(ok.headers.get("strict-transport-security")).toBe(
      STRICT_TRANSPORT_SECURITY,
    );

    const refused = await send(env(), "/nothing-here");
    expect(refused.status).toBe(404);
    expect(refused.headers.get("strict-transport-security")).toBe(
      STRICT_TRANSPORT_SECURITY,
    );

    const page = await handleRequest(
      new Request(`${ORIGIN}/policy`, { headers: { accept: "text/html" } }),
      env(),
      { now: NOW },
    );
    expect(page.headers.get("content-type")).toContain("text/html");
    expect(page.headers.get("strict-transport-security")).toBe(
      STRICT_TRANSPORT_SECURITY,
    );
  }, 120_000);
});
