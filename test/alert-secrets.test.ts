/**
 * An alert endpoint's shared secret, wrapped at rest (decision D-118 item a).
 *
 * Migration 0015 left the subscriber's HMAC secret in a plain column and said
 * so in its own comment: a copy of the database was a copy of every
 * subscriber's signing key, and anybody holding one could forge an alert that
 * verified. 0026 adds `secret_wrapped` and M25a fills it — AES-GCM under a key
 * derived from the ALERT_SIGNING_KEY Worker secret with HKDF-SHA-256, the salt
 * a constant and the info the endpoint's own id.
 *
 * What these tests hold the build to, and each of them is a way the change
 * could be worthless:
 *
 * - the round trip gives back the exact string the subscriber was handed, so
 *   nothing about a signature changes;
 * - a wrong key does not unwrap, which is what makes the column ciphertext
 *   rather than obfuscation, and it FAILS rather than returning something;
 * - one endpoint's ciphertext cannot be unwrapped as another's, which is what
 *   the per-endpoint info buys;
 * - the legacy rows 0015 wrote are converted by the sweep's own bounded pass,
 *   a few per run, and the plain column is nulled in the same statement;
 * - and a subscriber's deliveries are signed identically before and after its
 *   row was wrapped — which is the whole promise: the at-rest change is
 *   invisible on the wire.
 *
 * Against miniflare's D1 with every migration applied, an injected clock, and a
 * `fetch` that answers because the test said so.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  alertSignatureHeader,
  signAlert,
  unwrapAlertSecret,
  wrapAlertSecret,
} from "../src/alerts.js";
import { appendEvent, type Event } from "../src/events.js";
import { KEY_PREFIX, keyHash } from "../src/keys.js";
import { ALERT_SECRETS_WRAPPED_PER_RUN } from "../src/policy.js";
import {
  alertEndpoint,
  countPlainSecretEndpoints,
  putAlertDeliveries,
  putAlertEndpoint,
  setAlertCursor,
} from "../src/storage/alerts.js";
import type { D1Like } from "../src/storage/d1.js";
import { putKey } from "../src/storage/keys.js";
import { appendEvents } from "../src/storage/repository.js";
import { handleAlerts, runAlertStep } from "../src/worker/alerts.js";
import type { Env } from "../src/worker/env.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The injected clock: nothing here reads a wall clock. */
const NOW = new Date("2026-09-18T00:05:00.000Z");
const AT = NOW.toISOString();

/** The maintainer's wrapping key, as a Worker secret would carry it. */
const SIGNING_KEY = "alert-signing-key-for-tests-only-0123456789";

/** The plain secret the legacy rows carry. */
const PLAIN = "c2VjcmV0LWZvci1zaWduaW5nLWFsZXJ0cy1vbmx5";

const KEY_ID = "key_00000000000000a1";
const KEY_SECRET = `${KEY_PREFIX}${"a".repeat(43)}`;

/** A fetch that answers everything, recording the signature header it saw. */
function fakeFetch(): {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  readonly calls: { delivery: string; signature: string; body: string }[];
} {
  const calls: { delivery: string; signature: string; body: string }[] = [];
  const call = (async (input: RequestInfo | URL, init?: RequestInit) => {
    void input;
    const headers = new Headers(init?.headers);
    calls.push({
      delivery: headers.get("x-nomankind-alert") ?? "",
      signature: headers.get("x-nomankind-signature") ?? "",
      body: typeof init?.body === "string" ? init.body : "",
    });
    return new Response(null, { status: 200 });
  }) as ReturnType<typeof fakeFetch>;
  Object.defineProperty(call, "calls", { value: calls });
  return call;
}

/** One endpoint row, straight into the store. */
async function endpoint(
  db: D1Like,
  id: string,
  options: { readonly wrapped?: string } = {},
): Promise<void> {
  await putAlertEndpoint(db, {
    id,
    keyId: KEY_ID,
    url: `https://hook.example.com/${id}`,
    secret: options.wrapped ?? PLAIN,
    wrapped: options.wrapped !== undefined,
    domain: null,
    subject: null,
    category: null,
    kinds: null,
    createdAt: AT,
  });
}

/** One pending delivery for an endpoint, due now. */
async function delivery(
  db: D1Like,
  id: string,
  endpointId: string,
): Promise<void> {
  await putAlertDeliveries(db, [
    {
      id,
      endpointId,
      eventSeq: 0,
      kind: "submitted",
      entryId: "nmk_0000000000000000000000000000000a",
      body: { id, kind: "submitted" },
      nextAt: AT,
      createdAt: AT,
    },
  ]);
}

describe("wrapping an alert endpoint's secret", () => {
  it("gives back exactly what went in", async () => {
    const wrapped = await wrapAlertSecret(SIGNING_KEY, "hook_1", PLAIN);
    expect(wrapped).not.toContain(PLAIN);
    expect(await unwrapAlertSecret(SIGNING_KEY, "hook_1", wrapped)).toBe(PLAIN);
  });

  it("draws a fresh IV every time", async () => {
    // Two wrappings of one secret are two different strings, so a database
    // holding two identical ciphertexts is not holding evidence that two
    // subscribers share a secret.
    const first = await wrapAlertSecret(SIGNING_KEY, "hook_1", PLAIN);
    const second = await wrapAlertSecret(SIGNING_KEY, "hook_1", PLAIN);
    expect(first).not.toBe(second);
    expect(await unwrapAlertSecret(SIGNING_KEY, "hook_1", second)).toBe(PLAIN);
  });

  it("does not unwrap under the wrong key", async () => {
    const wrapped = await wrapAlertSecret(SIGNING_KEY, "hook_1", PLAIN);
    // GCM's tag is what makes this a refusal rather than a delivery signed with
    // rubbish: the ciphertext does not authenticate, so nothing comes back.
    expect(await unwrapAlertSecret(`${SIGNING_KEY}x`, "hook_1", wrapped)).toBe(
      null,
    );
  });

  it("does not unwrap as another endpoint's", async () => {
    // The info is the endpoint's own id, so a row lifted from the table cannot
    // be read as somebody else's even by the maintainer's own key.
    const wrapped = await wrapAlertSecret(SIGNING_KEY, "hook_1", PLAIN);
    expect(await unwrapAlertSecret(SIGNING_KEY, "hook_2", wrapped)).toBe(null);
  });

  it("answers null for a string that is not the two-part shape", async () => {
    for (const bad of ["", ".", "nodot", "abc.", ".abc", "!!!.!!!"]) {
      expect(await unwrapAlertSecret(SIGNING_KEY, "hook_1", bad)).toBe(null);
    }
  });
});

describe("the endpoints table", () => {
  let store: TestDatabase;

  beforeAll(async () => {
    store = await openTestDatabase();
    await putKey(store.db, {
      id: KEY_ID,
      keyHash: await keyHash(KEY_SECRET),
      tier: "startup",
      status: "active",
      createdAt: AT,
      clientDay: "cs_alert_secrets",
    });
  });

  afterAll(async () => {
    await store.dispose();
  });

  it("holds one of the two columns and never both", async () => {
    await endpoint(store.db, "hook_plain0000000001");
    await endpoint(store.db, "hook_wrapped000000001", {
      wrapped: await wrapAlertSecret(SIGNING_KEY, "hook_wrapped000000001", PLAIN),
    });

    const plain = (await alertEndpoint(store.db, "hook_plain0000000001"))!;
    expect(plain.secret).toBe(PLAIN);
    expect(plain.secret_wrapped).toBeNull();

    const wrapped = (await alertEndpoint(store.db, "hook_wrapped000000001"))!;
    expect(wrapped.secret).toBeNull();
    expect(wrapped.secret_wrapped).not.toBeNull();
    expect(wrapped.secret_wrapped).not.toContain(PLAIN);
  });

  it("shows the secret once at the door and stores it wrapped", async () => {
    const env = { DB: store.db, ALERT_SIGNING_KEY: SIGNING_KEY } as unknown as Env;
    const response = await handleAlerts(
      new Request("https://app.example/keys/me/webhooks", {
        method: "POST",
        headers: { authorization: `Bearer ${KEY_SECRET}` },
        body: JSON.stringify({ url: "https://hook.example.com/new" }),
      }),
      env,
      { now: NOW },
    );
    expect(response?.status).toBe(201);
    const body = (await response!.json()) as Record<string, unknown>;
    const id = String(body["id"]);
    const shown = String(body["secret"]);
    expect(shown.length).toBeGreaterThan(0);

    // Shown once, and the row holds the ciphertext of exactly that string.
    const row = (await alertEndpoint(store.db, id))!;
    expect(row.secret).toBeNull();
    expect(row.secret_wrapped).not.toBeNull();
    expect(await unwrapAlertSecret(SIGNING_KEY, id, row.secret_wrapped!)).toBe(
      shown,
    );
  });

  it("stores it plain when no key is configured", async () => {
    const env = { DB: store.db } as unknown as Env;
    const response = await handleAlerts(
      new Request("https://app.example/keys/me/webhooks", {
        method: "POST",
        headers: { authorization: `Bearer ${KEY_SECRET}` },
        body: JSON.stringify({ url: "https://hook.example.com/unwrapped" }),
      }),
      env,
      { now: NOW },
    );
    expect(response?.status).toBe(201);
    const body = (await response!.json()) as Record<string, unknown>;
    const row = (await alertEndpoint(store.db, String(body["id"])))!;
    // Today's behaviour, unchanged: the gap is visible on /status rather than
    // turning into a half-migrated table.
    expect(row.secret).toBe(String(body["secret"]));
    expect(row.secret_wrapped).toBeNull();
  });
});

describe("the legacy pass", () => {
  let store: TestDatabase;

  beforeAll(async () => {
    store = await openTestDatabase();
    await putKey(store.db, {
      id: KEY_ID,
      keyHash: await keyHash(KEY_SECRET),
      tier: "startup",
      status: "active",
      createdAt: AT,
      clientDay: "cs_alert_legacy",
    });
    // More rows than one run may convert, so the bound is measurable.
    for (let index = 0; index < ALERT_SECRETS_WRAPPED_PER_RUN + 2; index += 1) {
      await endpoint(store.db, `hook_legacy${String(index).padStart(9, "0")}`);
    }
    // Nothing for the deriving half to do: the cursor is already at the head.
    await setAlertCursor(store.db, 0);
  });

  afterAll(async () => {
    await store.dispose();
  });

  it("wraps a bounded few per run and nulls the plain column", async () => {
    const total = ALERT_SECRETS_WRAPPED_PER_RUN + 2;
    expect(await countPlainSecretEndpoints(store.db)).toBe(total);

    const run = (): Promise<{ wrapped: number }> =>
      runAlertStep(
        store.db,
        {
          now: NOW,
          sealedHead: 0,
          fetch: fakeFetch(),
          origin: "",
          signingKey: SIGNING_KEY,
        },
        () => {},
      );

    const first = await run();
    expect(first.wrapped).toBe(ALERT_SECRETS_WRAPPED_PER_RUN);
    expect(await countPlainSecretEndpoints(store.db)).toBe(
      total - ALERT_SECRETS_WRAPPED_PER_RUN,
    );

    const second = await run();
    expect(second.wrapped).toBe(total - ALERT_SECRETS_WRAPPED_PER_RUN);
    expect(await countPlainSecretEndpoints(store.db)).toBe(0);

    // And a third run finds nothing: the pass is one empty index seek from here
    // on, which is where every deployment that sets the key ends up.
    const third = await run();
    expect(third.wrapped).toBe(0);

    // Every row now holds the ciphertext of the secret it always held.
    const row = (await alertEndpoint(store.db, "hook_legacy000000000"))!;
    expect(row.secret).toBeNull();
    expect(await unwrapAlertSecret(SIGNING_KEY, row.id, row.secret_wrapped!)).toBe(
      PLAIN,
    );
  });

  it("wraps nothing when no key is configured", async () => {
    await endpoint(store.db, "hook_unconfigured001");
    const report = await runAlertStep(
      store.db,
      { now: NOW, sealedHead: 0, fetch: fakeFetch(), origin: "" },
      () => {},
    );
    expect(report.wrapped).toBe(0);
    const row = (await alertEndpoint(store.db, "hook_unconfigured001"))!;
    expect(row.secret).toBe(PLAIN);
    expect(row.secret_wrapped).toBeNull();
  });
});

describe("delivery signatures", () => {
  let store: TestDatabase;

  beforeAll(async () => {
    store = await openTestDatabase();
    await putKey(store.db, {
      id: KEY_ID,
      keyHash: await keyHash(KEY_SECRET),
      tier: "startup",
      status: "active",
      createdAt: AT,
      clientDay: "cs_alert_delivery",
    });
    // One event so there is a log at all; the step's deriving half has nothing
    // to do because the cursor is moved to the head.
    const log: Event[] = await appendEvent([], {
      at: AT,
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: [] },
    });
    await appendEvents(store.db, log);
    await setAlertCursor(store.db, log[log.length - 1]!.seq);
    await endpoint(store.db, "hook_signature000001");
  });

  afterAll(async () => {
    await store.dispose();
  });

  it("are the same before and after the row was wrapped", async () => {
    // The subscriber's own verifier: the secret it was handed at the door, over
    // the timestamp and the body it received. Nothing it does changes when the
    // column does — which is the whole promise of the at-rest change.
    const before = fakeFetch();
    await delivery(store.db, "alert_before00000001", "hook_signature000001");
    await runAlertStep(
      store.db,
      {
        now: NOW,
        sealedHead: 0,
        fetch: before,
        origin: "",
        signingKey: SIGNING_KEY,
      },
      () => {},
    );
    expect(before.calls.length).toBe(1);

    // That run also wrapped the row, so the next delivery is signed out of the
    // ciphertext.
    const row = (await alertEndpoint(store.db, "hook_signature000001"))!;
    expect(row.secret).toBeNull();

    const after = fakeFetch();
    await delivery(store.db, "alert_after000000001", "hook_signature000001");
    await runAlertStep(
      store.db,
      {
        now: NOW,
        sealedHead: 0,
        fetch: after,
        origin: "",
        signingKey: SIGNING_KEY,
      },
      () => {},
    );
    expect(after.calls.length).toBe(1);

    const timestamp = Math.floor(NOW.getTime() / 1000);
    for (const call of [before.calls[0]!, after.calls[0]!]) {
      expect(call.signature).toBe(
        alertSignatureHeader(
          timestamp,
          await signAlert(PLAIN, timestamp, call.body),
        ),
      );
    }
  });

  it("are not sent at all when the secret cannot be recovered", async () => {
    // A wrapped row whose key is absent or has changed: the delivery waits on
    // the retry ladder rather than going out signed with something no
    // subscriber can check. A signature only the sender can verify is worse
    // than a missing alert.
    await endpoint(store.db, "hook_wrongkey000001", {
      wrapped: await wrapAlertSecret(SIGNING_KEY, "hook_wrongkey000001", PLAIN),
    });
    await delivery(store.db, "alert_wrongkey000001", "hook_wrongkey000001");
    const call = fakeFetch();
    const report = await runAlertStep(
      store.db,
      {
        now: NOW,
        sealedHead: 0,
        fetch: call,
        origin: "",
        signingKey: `${SIGNING_KEY}-rotated`,
      },
      () => {},
    );
    expect(
      call.calls.some((one) => one.delivery === "alert_wrongkey000001"),
    ).toBe(false);
    expect(report.delivered + report.retried).toBeGreaterThan(0);
  });
});
