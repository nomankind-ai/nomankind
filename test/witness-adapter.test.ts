/**
 * The witness adapter, against a registry that exists only in this file.
 *
 * The M16 capture pins the verifier (test/registry-proof.test.ts) against the
 * real registry's wire; what is under test here is the *collector* — which
 * lines it keeps, which it drops, and whether what it hands back survives
 * src/witness.ts's rule. So the log is generated with test/helpers/registry-
 * tree.ts, the checkpoints are signed with a test registry key, and the witness
 * files are written with test witness keys: every proof is real, and not one
 * packet leaves the machine.
 *
 * The properties that matter most are the negative ones. A witness whose
 * directory row moved is dropped rather than followed. A "first observation"
 * line is never returned, however new it is. And the bearer credential appears
 * on exactly one request header and in nothing this module ever gives back.
 */

import { readFileSync } from "node:fs";

import { beforeAll, describe, expect, it } from "vitest";

import {
  MOCK_WITNESSES,
  MOCK_WITNESS_KEYS,
  MockWitnessAdapter,
  RegistryWitnessAdapter,
  UnavailableWitnessAdapter,
  pinnedWitnessesFor,
  sealingAgentIdFor,
  witnessAdapterFor,
  type WitnessPin,
} from "../src/adapters/witness.js";
import { base64urlDecode, base64urlEncode } from "../src/encoding.js";
import {
  AGENT_ID_PREFIX,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
  importPrivateKeyPkcs8,
  signBytes,
  verifyBytes,
} from "../src/identity.js";
import { REGISTRY, WITNESS_FILE_TAIL_BYTES, WITNESS_PIN } from "../src/policy.js";
import {
  registryCheckpointPayload,
  registryLeafHash,
  registryWitnessPayload,
  verifyRegistryInclusion,
} from "../src/registry-proof.js";
import type { Seal } from "../src/seal.js";
import { checkWitnesses, signWitness } from "../src/witness.js";
import type { Env } from "../src/worker/env.js";
import { consistencyOf, leafOf, pathOf, rootOf } from "./helpers/registry-tree.js";

const encoder = new TextEncoder();

const ORIGIN = "https://registry.test";
const LOG = "identity_events";
const LABEL = "nomankind-seal";
const HANDLE = "nomankind-agent";
/** Never appears in a returned value; the tests below check that it does not. */
const CREDENTIAL = "bearer-credential-that-must-never-escape";
const NOW = new Date("2026-09-08T12:00:00.000Z");

/** The seal hash the fingerprint is taken from. */
const SEAL_HASH = `sha256:${"ab".repeat(32)}`;
const FINGERPRINT = "ab".repeat(32);

/**
 * Our memory.seal identity event: the fourth leaf, and `SIZE` is the head the
 * registry answers the inclusion proof under — the *earliest* checkpoint that
 * covers the leaf, which is what the real registry does. The log kept growing
 * after that, to `TOTAL`, because that is the other half of production: a
 * witness countersigns whatever head is current when it runs, so the head it
 * signed is normally later than the proof's.
 */
const SIZE = 8;
const TOTAL = 12;
/** A head later than the proof's, and not a power of two, so the fold is real. */
const LATER_SIZE = 11;
const LEAF_INDEX = 3;
const EVENT_ID = 103;

/**
 * The row id the registry's seals table gave the same seal. A different number
 * from the identity event's, because it is a different thing: reading it as an
 * event id is the defect this file's newer tests pin down.
 */
const SEAL_ROW_ID = 4281;

/** The leaf a proof for any other event answers with: unrelated to ours. */
const OTHER_LEAF_INDEX = 1;

/** A key pair in every form the wire and the adapter want it in. */
interface TestKey {
  publicKey: string;
  privateKey: CryptoKey;
  pkcs8: string;
}

async function makeKey(): Promise<TestKey> {
  const pair = await generateKeypair();
  return {
    publicKey: base64urlEncode(await exportPublicKeyRaw(pair.publicKey)),
    privateKey: pair.privateKey,
    pkcs8: base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey)),
  };
}

let registryKey: TestKey;
let sealingKey: TestKey;
let alpha: TestKey;
let beta: TestKey;
let gamma: TestKey;

let eventHashes: string[];
let leaves: string[];

/** A signed checkpoint of the first `size` leaves. */
async function checkpointAt(size: number): Promise<{
  id: number;
  tree_size: number;
  root: string;
  sig: string;
  created_at: number;
}> {
  const root = await rootOf(leaves.slice(0, size));
  const created_at = 1788922500000 + size;
  const sig = base64urlEncode(
    await signBytes(
      registryKey.privateKey,
      registryCheckpointPayload({
        log: LOG,
        tree_size: size,
        root,
        created_at,
      }),
    ),
  );
  return { id: size, tree_size: size, root, sig, created_at };
}

/** One countersignature line of a witness's published file. */
async function countersignatureLine(
  witness: TestKey,
  size: number,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const checkpoint = await checkpointAt(size);
  const witness_sig = base64urlEncode(
    await signBytes(
      witness.privateKey,
      registryWitnessPayload({
        registry: ORIGIN,
        log: LOG,
        tree_size: size,
        root: checkpoint.root,
      }),
    ),
  );
  return {
    type: "witness-countersignature",
    at: new Date(checkpoint.created_at).toISOString(),
    registry: ORIGIN,
    log: LOG,
    tree_size: size,
    root: checkpoint.root,
    created_at: checkpoint.created_at,
    registry_sig: checkpoint.sig,
    consistency: `verified from ${size}`,
    status: "countersigned",
    witness_sig,
    witness_public_key: witness.publicKey,
    ...overrides,
  };
}

function fileOf(lines: readonly Record<string, unknown>[]): string {
  return `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`;
}

let pinAlpha: WitnessPin;
let pinBeta: WitnessPin;
let pinGamma: WitnessPin;

/** What the fake registry answers with, per test. */
interface FakeOptions {
  /** The directory rows, defaulting to alpha and beta pinned and gamma rotated. */
  directory?: { id: number; public_key: string }[];
  files?: Record<string, string>;
  seal?: { status: number; body: unknown };
  /** The citizen record, defaulting to one that lists our `memory.seal` event. */
  record?: unknown;
  /** The citizen record per `events_since` page, for the paging test. */
  recordPages?: Record<string, unknown>;
  /** Whether the directory endpoint answers at all. */
  witnessesStatus?: number;
  /** The consistency endpoint's body, for the tests that corrupt the bridge. */
  consistency?: (from: number, to: number) => Promise<unknown> | unknown;
}

/** Our `memory.seal` identity event, as the citizen record lists it. */
function sealEvent(): Record<string, unknown> {
  return {
    id: EVENT_ID,
    kind: "memory.seal",
    detail: `label='${LABEL}' sha256=${FINGERPRINT}, signed by thumbprint`,
    created_at: 1788922500000,
    prev_hash: eventHashes[LEAF_INDEX - 1],
    hash: eventHashes[LEAF_INDEX],
    leaf_index: LEAF_INDEX,
    proof: [],
  };
}

/** A citizen record listing these events and nothing more to page to. */
function recordOf(events: readonly Record<string, unknown>[]): unknown {
  return {
    handle: HANDLE,
    events,
    events_total: events.length,
    events_returned: events.length,
    events_has_more: false,
    // The convenience list names the registry's own seal row, which is exactly
    // the id that must never be read as an identity event id.
    seals: [{ id: SEAL_ROW_ID, hash: FINGERPRINT, label: LABEL }],
  };
}

interface FakeCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

/** A registry, three witness files and a seal endpoint, all in memory. */
async function fakeRegistry(options: FakeOptions = {}): Promise<{
  fetch: typeof fetch;
  calls: FakeCall[];
}> {
  const calls: FakeCall[] = [];
  const directory = options.directory ?? [
    { id: pinAlpha.id, public_key: alpha.publicKey },
    { id: pinBeta.id, public_key: beta.publicKey },
    // The pin says gamma's key; the directory says another. A moved row is
    // dropped for the run, never followed.
    { id: pinGamma.id, public_key: (await makeKey()).publicKey },
  ];
  const files = options.files ?? {};

  const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  const fetchFn = async function (
    this: unknown,
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Illegal invocation");
    }
    const raw = String(input);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(
      (init?.headers ?? {}) as Record<string, string>,
    )) {
      headers[name.toLowerCase()] = value;
    }
    const bodyInit = init?.body;
    calls.push({
      url: raw,
      method: init?.method ?? "GET",
      headers,
      body: typeof bodyInit === "string" ? bodyInit : null,
    });

    const url = new URL(raw);

    if (url.origin === ORIGIN && url.pathname === "/api/seal") {
      // The registry's own shape: the seal row's id, and the anchoring identity
      // event named by its hash under `chained` and by nothing else.
      const answer = options.seal ?? {
        status: 200,
        body: {
          ok: true,
          seal: { id: SEAL_ROW_ID, hash: FINGERPRINT, label: LABEL },
          chained: eventHashes[LEAF_INDEX],
        },
      };
      return json(answer.body, answer.status);
    }

    if (url.origin === ORIGIN && url.pathname === `/api/record/${HANDLE}`) {
      const since = url.searchParams.get("events_since");
      if (options.recordPages !== undefined) {
        const page = options.recordPages[since ?? ""];
        return page === undefined
          ? json({ error: "not found" }, 404)
          : json(page);
      }
      return json(options.record ?? recordOf([sealEvent()]));
    }

    if (url.origin === ORIGIN && url.pathname === "/api/witnesses") {
      const status = options.witnessesStatus ?? 200;
      if (status !== 200) return json({ error: "unavailable" }, status);
      return json({ witnesses: directory, count: directory.length });
    }

    if (url.origin === ORIGIN && url.pathname === "/api/proof") {
      // A proof endpoint answers about the event it was asked about: ask it for
      // the seal row's id and it answers some other event entirely, which is
      // what the production defect did.
      const asked = Number(url.searchParams.get("event"));
      const leaf = asked === EVENT_ID ? LEAF_INDEX : OTHER_LEAF_INDEX;
      return json({
        log: url.searchParams.get("log"),
        event: {
          id: asked,
          hash: eventHashes[leaf],
          leaf_index: leaf,
        },
        // Against the earliest head that covers the leaf, never the newest:
        // the registry's own behaviour, and the reason a bridge runs forward.
        checkpoint: await checkpointAt(SIZE),
        proof: await pathOf(leaves.slice(0, SIZE), leaf),
      });
    }

    if (url.origin === ORIGIN && url.pathname === "/api/checkpoint/consistency") {
      const from = Number(url.searchParams.get("from"));
      const to = Number(url.searchParams.get("to"));
      // The registry only proves the smaller tree into the larger; asking it
      // the other way round is a refusal, not an answer.
      if (!(from >= 0 && from <= to)) {
        return json({ error: "from must not exceed to" }, 400);
      }
      if (options.consistency !== undefined) {
        return json(await options.consistency(from, to));
      }
      return json({
        log: url.searchParams.get("log"),
        from: await checkpointAt(from),
        to: await checkpointAt(to),
        proof: await consistencyOf(leaves.slice(0, to), from),
      });
    }

    const file = files[raw];
    if (file !== undefined) {
      const range = headers["range"];
      const match = /^bytes=-(\d+)$/.exec(range ?? "");
      if (match !== null) {
        const tail = Number(match[1]);
        if (tail < file.length) {
          return new Response(file.slice(file.length - tail), { status: 206 });
        }
      }
      return new Response(file, { status: 200 });
    }

    return new Response("not found", { status: 404 });
  } as unknown as typeof fetch;

  return { fetch: fetchFn, calls };
}

/** A seal whose fingerprint is already in the registry log. */
function sealedSeal(): Seal {
  return {
    seq: 0,
    first_seq: 0,
    last_seq: 0,
    size: 1,
    root: `sha256:${"cd".repeat(32)}`,
    sealed_at: NOW.toISOString(),
    prev_hash: null,
    hash: SEAL_HASH,
    witnesses: [],
    registry: {
      registry: ORIGIN,
      handle: HANDLE,
      label: LABEL,
      event_id: EVENT_ID,
      event_hash: eventHashes[LEAF_INDEX]!,
      receipt: null,
      sealed_at: NOW.toISOString(),
    },
  };
}

/**
 * The same seal as production's seal 0 kept it: the registry's seal row id where
 * the identity event id belongs, and no chain hash at all.
 */
function sealWithSealRowId(): Seal {
  const seal = sealedSeal();
  seal.registry = {
    ...seal.registry!,
    event_id: SEAL_ROW_ID,
    event_hash: null,
  };
  return seal;
}

/**
 * A fetch that answers one witness file itself, so a test can answer a ranged
 * read the way a real server does; everything else goes to the fake registry.
 */
function fileServer(
  inner: typeof fetch,
  url: string,
  serve: (range: string | undefined) => Response,
): { fetch: typeof fetch; ranges: (string | undefined)[] } {
  const ranges: (string | undefined)[] = [];
  const fetchFn = async function (
    this: unknown,
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    if (String(input) !== url) return inner(input, init);
    const headers = (init?.headers ?? {}) as Record<string, string>;
    ranges.push(headers["range"]);
    return serve(headers["range"]);
  } as unknown as typeof fetch;
  return { fetch: fetchFn, ranges };
}

function adapterWith(fetchFn: typeof fetch, tailBytes?: number) {
  return new RegistryWitnessAdapter({
    fetch: fetchFn,
    origin: ORIGIN,
    registryPublicKey: registryKey.publicKey,
    log: LOG,
    label: LABEL,
    handle: HANDLE,
    credential: CREDENTIAL,
    privateKeyPkcs8: sealingKey.pkcs8,
    pin: [pinAlpha, pinBeta, pinGamma],
    ...(tailBytes === undefined ? {} : { tailBytes }),
  });
}

/** The rule's context for the test pin: three operators, none of them ours. */
function testContext() {
  return {
    witnesses: [
      { agent: AGENT_ID_PREFIX + alpha.publicKey, operator: pinAlpha.operator },
      { agent: AGENT_ID_PREFIX + beta.publicKey, operator: pinBeta.operator },
      { agent: AGENT_ID_PREFIX + gamma.publicKey, operator: pinGamma.operator },
    ],
    maintainerOperators: new Set<string>(["nomankind"]),
    ineligibleAgents: new Set<string>(),
    registry: { origin: ORIGIN, public_key: registryKey.publicKey },
  };
}

beforeAll(async () => {
  registryKey = await makeKey();
  sealingKey = await makeKey();
  alpha = await makeKey();
  beta = await makeKey();
  gamma = await makeKey();

  eventHashes = Array.from({ length: TOTAL }, (_, index) =>
    (index + 1).toString(16).padStart(64, "0"),
  );
  leaves = await Promise.all(eventHashes.map((hash) => leafOf(hash)));

  pinAlpha = {
    id: 6,
    operator: "alpha.example",
    public_key: alpha.publicKey,
    url: "https://files.test/alpha.jsonl",
  };
  pinBeta = {
    id: 7,
    operator: "beta.example",
    public_key: beta.publicKey,
    url: "https://files.test/beta.jsonl",
  };
  pinGamma = {
    id: 8,
    operator: "gamma.example",
    public_key: gamma.publicKey,
    url: "https://files.test/gamma.jsonl",
  };
});

/** Alpha countersigns an earlier head; beta countersigns the proved head. */
async function witnessFiles(): Promise<Record<string, string>> {
  return {
    [pinAlpha.url]: fileOf([
      // Another log entirely: a pointer to nothing about identity_events.
      await countersignatureLine(alpha, SIZE, {
        log: "ledger",
        padding: "x".repeat(400),
      }),
      // A newer head, but a first observation: it attests nothing about what
      // came before it, which is the guarantee being borrowed.
      await countersignatureLine(alpha, SIZE, {
        consistency: "first observation",
      }),
      // A refusal at the same size, for the same reason it must not be used.
      await countersignatureLine(alpha, SIZE, { status: "refused" }),
      await countersignatureLine(alpha, 6),
    ]),
    [pinBeta.url]: fileOf([await countersignatureLine(beta, SIZE)]),
    [pinGamma.url]: fileOf([await countersignatureLine(gamma, SIZE)]),
  };
}

describe("MockWitnessAdapter", () => {
  it("signs the direct form, and the rule accepts both witnesses", async () => {
    const adapter = new MockWitnessAdapter();
    expect(adapter.kind).toBe("mock");
    expect(await adapter.seal(sealedSeal(), NOW)).toBeNull();

    const signatures = await adapter.collect(sealedSeal(), NOW);
    expect(signatures).toHaveLength(2);
    // The direct form carries no head: the mock has no registry to sign one.
    expect(signatures.every((entry) => entry.head === undefined)).toBe(true);

    const check = await checkWitnesses(SEAL_HASH, signatures, {
      witnesses: MOCK_WITNESSES,
      maintainerOperators: new Set<string>(),
      ineligibleAgents: new Set<string>(),
      registry: null,
    });
    expect(check.ok).toBe(true);
    expect(check.ok && check.witnesses.map((w) => w.operator)).toEqual([
      "mock-witness-a.example",
      "mock-witness-b.example",
    ]);
  });

  it("publishes the keys, so a test can sign as a mock witness", async () => {
    expect(MOCK_WITNESS_KEYS).toHaveLength(MOCK_WITNESSES.length);
    const key = await importPrivateKeyPkcs8(base64urlDecode(MOCK_WITNESS_KEYS[0]!));
    const signature = await signWitness(key, SEAL_HASH);

    const check = await checkWitnesses(
      SEAL_HASH,
      [{ agent: MOCK_WITNESSES[0]!.agent, signature }],
      {
        witnesses: MOCK_WITNESSES,
        maintainerOperators: new Set<string>(),
        ineligibleAgents: new Set<string>(),
        registry: null,
      },
    );
    expect(check.ok).toBe(true);
  });
});

describe("pinnedWitnessesFor", () => {
  it("gives production the three D-054 agents and the pinned registry", () => {
    const pinned = pinnedWitnessesFor("production");
    expect(pinned.witnesses).toHaveLength(3);
    expect(pinned.witnesses.map((witness) => witness.agent)).toEqual(
      WITNESS_PIN.map((row) => AGENT_ID_PREFIX + row.public_key),
    );
    expect(pinned.witnesses.map((witness) => witness.operator)).toEqual([
      "commonwealth",
      "head-of-experiments",
      "liveness",
    ]);
    expect(pinned.registry).toEqual({
      origin: REGISTRY.origin,
      public_key: REGISTRY.public_key,
    });
  });

  it("gives every other environment the mock set and no registry", () => {
    for (const environment of ["local", "demo", "", "preview"]) {
      const pinned = pinnedWitnessesFor(environment);
      expect(pinned.witnesses).toEqual(MOCK_WITNESSES);
      expect(pinned.registry).toBeNull();
    }
  });
});

describe("RegistryWitnessAdapter.seal", () => {
  it("signs the registry's payload and keeps what came back", async () => {
    const { fetch, calls } = await fakeRegistry();
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);

    expect(sealed).not.toBeNull();
    expect(sealed!.registry).toBe(ORIGIN);
    expect(sealed!.handle).toBe(HANDLE);
    expect(sealed!.label).toBe(LABEL);
    expect(sealed!.event_id).toBe(EVENT_ID);
    expect(sealed!.event_hash).toBe(eventHashes[LEAF_INDEX]);
    expect(sealed!.sealed_at).toBe(NOW.toISOString());
    expect(sealed!.receipt).toEqual({
      ok: true,
      seal: { id: SEAL_ROW_ID, hash: FINGERPRINT, label: LABEL },
      chained: eventHashes[LEAF_INDEX],
    });
    // The response's own id is the seal row's, and it is never stored as one.
    expect(sealed!.event_id).not.toBe(SEAL_ROW_ID);
    expect(
      calls.some((call) => call.url.includes(`/api/record/${HANDLE}`)),
    ).toBe(true);

    const post = calls.find((call) => call.url.endsWith("/api/seal"))!;
    expect(post.method).toBe("POST");
    expect(post.headers["authorization"]).toBe(`Bearer ${CREDENTIAL}`);
    expect(post.headers["user-agent"]).toBe("nomankind");

    const body = JSON.parse(post.body!) as {
      hash: string;
      label: string;
      signature: string;
    };
    expect(body.hash).toBe(FINGERPRINT);
    expect(body.label).toBe(LABEL);
    // The signature is over exactly the string the registry states, by the key
    // the maintainer set: `1f916.seal.v1:<handle>:<label>:<hash>`.
    expect(
      await verifyBytes(
        base64urlDecode(sealingKey.publicKey),
        encoder.encode(`1f916.seal.v1:${HANDLE}:${LABEL}:${FINGERPRINT}`),
        base64urlDecode(body.signature),
      ),
    ).toBe(true);
  });

  it("resolves a 409 through the citizen record, by fingerprint", async () => {
    const { fetch, calls } = await fakeRegistry({
      seal: { status: 409, body: { error: "already_sealed" } },
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);

    expect(sealed).not.toBeNull();
    // The conflict body names neither the event nor its hash, so both come from
    // the record: the event whose detail names our fingerprint.
    expect(sealed!.event_id).toBe(EVENT_ID);
    expect(sealed!.event_hash).toBe(eventHashes[LEAF_INDEX]);
    expect(sealed!.receipt).toEqual({ error: "already_sealed" });
    expect(
      calls.some((call) => call.url.includes(`/api/record/${HANDLE}`)),
    ).toBe(true);
  });

  it("never matches a memory.seal event under another label", async () => {
    // The same fingerprint sealed under someone else's label is someone else's
    // event, and a 409 leaves only the `detail` to tell them apart.
    const otherLabel = {
      ...sealEvent(),
      id: 4444,
      detail: `label='another-label' sha256=${FINGERPRINT}, signed by thumbprint`,
      hash: eventHashes[OTHER_LEAF_INDEX],
      leaf_index: OTHER_LEAF_INDEX,
    };
    const conflict = { status: 409, body: { error: "already_sealed" } };

    const { fetch } = await fakeRegistry({
      seal: conflict,
      record: recordOf([otherLabel]),
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);
    expect(sealed).not.toBeNull();
    expect(sealed!.event_id).toBeNull();
    expect(sealed!.event_hash).toBeNull();

    // Ours listed beside it is the one that is taken.
    const { fetch: both } = await fakeRegistry({
      seal: conflict,
      record: recordOf([otherLabel, sealEvent()]),
    });
    const resolved = await adapterWith(both).seal(sealedSeal(), NOW);
    expect(resolved!.event_id).toBe(EVENT_ID);
    expect(resolved!.event_hash).toBe(eventHashes[LEAF_INDEX]);
  });

  it("resolves a 200 that names no event the same way", async () => {
    const { fetch } = await fakeRegistry({
      seal: { status: 200, body: { seal: { id: SEAL_ROW_ID, hash: FINGERPRINT } } },
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);
    expect(sealed!.event_id).toBe(EVENT_ID);
    expect(sealed!.event_hash).toBe(eventHashes[LEAF_INDEX]);
  });

  it("keeps the chained hash and no id when the record has not listed it", async () => {
    const { fetch } = await fakeRegistry({
      // A record with the key-bind event and no seal event yet.
      record: recordOf([
        { id: 88, kind: "key-bind", detail: "Ed25519 key bound", hash: eventHashes[0] },
      ]),
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);

    expect(sealed).not.toBeNull();
    // Null, never the seal row id: the witness step resolves it on a later run.
    expect(sealed!.event_id).toBeNull();
    expect(sealed!.event_hash).toBe(eventHashes[LEAF_INDEX]);
  });

  it("pages the record's events with the parameter the route publishes", async () => {
    const filler = Array.from({ length: 3 }, (_, index) => ({
      id: 80 + index,
      kind: "key-bind",
      detail: "Ed25519 key bound",
      hash: eventHashes[index],
    }));
    const { fetch, calls } = await fakeRegistry({
      recordPages: {
        "": { ...(recordOf(filler) as object), events_has_more: true },
        "82": recordOf([sealEvent()]),
      },
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);

    expect(sealed!.event_id).toBe(EVENT_ID);
    expect(
      calls.some((call) => call.url.endsWith("?events_since=82")),
    ).toBe(true);
  });

  it("answers null when the registry refuses, and leaks no credential", async () => {
    const { fetch } = await fakeRegistry({
      seal: { status: 401, body: { error: "unauthorized" } },
    });
    const adapter = adapterWith(fetch);
    const sealed = await adapter.seal(sealedSeal(), NOW);
    expect(sealed).toBeNull();

    // Nothing this adapter hands back — receipt included — carries the
    // credential or the sealing key.
    const { fetch: ok } = await fakeRegistry();
    const good = await adapterWith(ok).seal(sealedSeal(), NOW);
    const rendered = JSON.stringify(good);
    expect(rendered).not.toContain(CREDENTIAL);
    expect(rendered).not.toContain(sealingKey.pkcs8);
  });

  it("answers null rather than throwing when the network is gone", async () => {
    const dead = (async () => {
      throw new TypeError("network down");
    }) as unknown as typeof fetch;
    await expect(adapterWith(dead).seal(sealedSeal(), NOW)).resolves.toBeNull();
    await expect(adapterWith(dead).collect(sealedSeal(), NOW)).resolves.toEqual([]);
  });

  it("never calls fetch with the adapter itself as the receiver", async () => {
    // workerd's own fetch throws exactly this when it is called on anything but
    // the global object, and Node's does not — the M13 lesson.
    const { fetch } = await fakeRegistry();
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);
    expect(sealed).not.toBeNull();
  });
});

describe("RegistryWitnessAdapter.collect", () => {
  it("yields countersignatures the witness rule accepts", async () => {
    const { fetch } = await fakeRegistry({ files: await witnessFiles() });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);

    expect(signatures).toHaveLength(2);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + alpha.publicKey,
      AGENT_ID_PREFIX + beta.publicKey,
    ]);

    const check = await checkWitnesses(SEAL_HASH, signatures, testContext());
    expect(check.ok).toBe(true);
    expect(check.ok && check.witnesses.map((witness) => witness.operator)).toEqual(
      ["alpha.example", "beta.example"],
    );
  });

  it("bridges an earlier head and leaves a matching head unbridged", async () => {
    const { fetch } = await fakeRegistry({ files: await witnessFiles() });
    const [first, second] = await adapterWith(fetch).collect(sealedSeal(), NOW);

    // Alpha's newest usable line is the one at six, because the newer lines are
    // a first observation and a refusal. The gap to the proved head is closed
    // by a consistency proof.
    expect(first!.head!.tree_size).toBe(6);
    expect(first!.evidence!.consistency).toBe("verified from 6");
    expect(first!.evidence!.proved_at.tree_size).toBe(SIZE);
    expect(first!.evidence!.consistency_proof.length).toBeGreaterThan(0);
    expect(first!.evidence!.leaf_index).toBe(LEAF_INDEX);
    expect(first!.evidence!.event_hash).toBe(eventHashes[LEAF_INDEX]);

    // Beta signed the very head the proof was fetched against: nothing to
    // bridge, so the consistency path is empty.
    expect(second!.head!.tree_size).toBe(SIZE);
    expect(second!.evidence!.consistency_proof).toEqual([]);
  });

  it("bridges forward to a head countersigned after the proof's", async () => {
    // Production's shape: the proof is answered under the earliest head that
    // covers our leaf, and the witness countersigned a later one.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([await countersignatureLine(alpha, LATER_SIZE)]);

    const { fetch, calls } = await fakeRegistry({ files });
    const [first] = await adapterWith(fetch).collect(sealedSeal(), NOW);

    expect(first!.head!.tree_size).toBe(LATER_SIZE);
    expect(first!.evidence!.proved_at.tree_size).toBe(SIZE);
    expect(first!.evidence!.consistency_proof.length).toBeGreaterThan(0);

    // Asked the only way the registry can answer: the smaller tree into the
    // larger, which here means from the proof's head to the countersigned one.
    const asked = calls.filter((call) =>
      call.url.includes("/api/checkpoint/consistency"),
    );
    expect(asked.some((call) => call.url.includes(`from=${SIZE}&to=${LATER_SIZE}`))).toBe(
      true,
    );
    expect(
      asked.some((call) => call.url.includes(`from=${LATER_SIZE}&to=${SIZE}`)),
    ).toBe(false);

    // And the rule accepts what came back, which is the whole point.
    const check = await checkWitnesses(SEAL_HASH, [first!], testContext());
    expect(check.ok).toBe(true);
  });

  it("takes the newest line whichever side of the proof's head it falls", async () => {
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([
      await countersignatureLine(alpha, 6),
      await countersignatureLine(alpha, LATER_SIZE),
      await countersignatureLine(alpha, SIZE),
    ]);

    const { fetch } = await fakeRegistry({ files });
    const [first] = await adapterWith(fetch).collect(sealedSeal(), NOW);
    expect(first!.head!.tree_size).toBe(LATER_SIZE);
  });

  it("refuses a head that does not cover our leaf, however new the line", async () => {
    // A head of three leaves cannot cover leaf three, so there is nothing to
    // bridge to and the line is not usable at any size.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([
      await countersignatureLine(alpha, LEAF_INDEX),
    ]);

    const { fetch, calls } = await fakeRegistry({ files });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);

    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
    // Never even asked for a bridge to it.
    expect(
      calls.some((call) => call.url.includes(`from=${LEAF_INDEX}`)),
    ).toBe(false);
  });

  it("refuses a bridge whose from head is not the head the proof was fetched at", async () => {
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([await countersignatureLine(alpha, LATER_SIZE)]);

    // Real proof, real heads, but the `from` head is a different tree than the
    // one our inclusion proof folds to: a proof of some other pair of heads.
    const { fetch } = await fakeRegistry({
      files,
      consistency: async (_from, to) => ({
        log: LOG,
        from: await checkpointAt(6),
        to: await checkpointAt(to),
        proof: await consistencyOf(leaves.slice(0, to), 6),
      }),
    });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
  });

  it("refuses a bridge whose to head is not the countersigned one", async () => {
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([await countersignatureLine(alpha, LATER_SIZE)]);

    const { fetch } = await fakeRegistry({
      files,
      consistency: async (from) => ({
        log: LOG,
        from: await checkpointAt(from),
        to: await checkpointAt(TOTAL),
        proof: await consistencyOf(leaves.slice(0, TOTAL), from),
      }),
    });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
  });

  it("refuses a bridge whose path does not fold", async () => {
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([await countersignatureLine(alpha, LATER_SIZE)]);

    const { fetch } = await fakeRegistry({
      files,
      consistency: async (from, to) => ({
        log: LOG,
        from: await checkpointAt(from),
        to: await checkpointAt(to),
        // The right shape and the wrong hashes: both heads are named correctly
        // and the path proves nothing about either.
        proof: (await consistencyOf(leaves.slice(0, to), from)).map(() =>
          "0".repeat(64),
        ),
      }),
    });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
  });

  it("never returns a first-observation line", async () => {
    const files = await witnessFiles();
    // Alpha's file now holds nothing but the first observation.
    files[pinAlpha.url] = fileOf([
      await countersignatureLine(alpha, SIZE, { consistency: "first observation" }),
    ]);
    const { fetch } = await fakeRegistry({ files });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);

    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
  });

  it("skips a witness whose directory key moved", async () => {
    const { fetch, calls } = await fakeRegistry({ files: await witnessFiles() });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);

    expect(
      signatures.some((entry) => entry.agent.includes(gamma.publicKey)),
    ).toBe(false);
    // Dropped before its file was ever read: code never follows a moved key.
    expect(calls.some((call) => call.url === pinGamma.url)).toBe(false);
  });

  it("reads only the tail of a long file and drops the partial first line", async () => {
    const files = await witnessFiles();
    const alphaFile = files[pinAlpha.url]!;
    // Cut ten bytes into the long first line, so the tail begins mid-record.
    const kept = alphaFile.slice(alphaFile.indexOf("\n") + 1);
    const tailBytes = kept.length + 10;

    const { fetch, calls } = await fakeRegistry({ files });
    const signatures = await adapterWith(fetch, tailBytes).collect(
      sealedSeal(),
      NOW,
    );

    const request = calls.find((call) => call.url === pinAlpha.url)!;
    expect(request.headers["range"]).toBe(`bytes=-${tailBytes}`);
    expect(signatures).toHaveLength(2);
    expect(signatures[0]!.head!.tree_size).toBe(6);
  });

  it("reads the whole file when the tail is more than there is to read", async () => {
    // A file smaller than the tail: raw.githubusercontent.com answers 416
    // rather than sending what it has (two of the three pinned files were under
    // the tail on 2026-09-09), and the retry without a range is the whole file,
    // so its first line is whole and counts.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([
      // The only usable line is the first one: drop it and alpha has nothing.
      await countersignatureLine(alpha, 6),
      await countersignatureLine(alpha, SIZE, { consistency: "first observation" }),
    ]);
    const whole = files[pinAlpha.url]!;

    const inner = await fakeRegistry({ files });
    const { fetch, ranges } = fileServer(inner.fetch, pinAlpha.url, (range) =>
      range === undefined
        ? new Response(whole, { status: 200 })
        : new Response("", { status: 416 }),
    );

    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);

    // Asked for the tail first, then for the file, and read every line of it.
    expect(ranges).toEqual([`bytes=-${WITNESS_FILE_TAIL_BYTES}`, undefined]);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + alpha.publicKey,
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
    expect(signatures[0]!.head!.tree_size).toBe(6);

    const check = await checkWitnesses(SEAL_HASH, signatures, testContext());
    expect(check.ok).toBe(true);
  });

  it("drops the first line of a real tail, however usable it looks", async () => {
    // The same file over a 206: the first line is a fragment of whatever record
    // the byte offset fell inside, so it is dropped unparsed and alpha, whose
    // only usable line that is, contributes nothing.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([
      await countersignatureLine(alpha, 6),
      await countersignatureLine(alpha, SIZE, { consistency: "first observation" }),
    ]);

    const { fetch } = await fakeRegistry({ files });
    const signatures = await adapterWith(
      fetch,
      files[pinAlpha.url]!.length - 5,
    ).collect(sealedSeal(), NOW);

    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
  });

  it("reads a ranged read answered 200 as the whole file", async () => {
    // A server may ignore the range and send everything; then nothing is
    // partial and the first line counts.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([
      await countersignatureLine(alpha, 6),
      await countersignatureLine(alpha, SIZE, { consistency: "first observation" }),
    ]);
    const whole = files[pinAlpha.url]!;

    const inner = await fakeRegistry({ files });
    const { fetch, ranges } = fileServer(
      inner.fetch,
      pinAlpha.url,
      () => new Response(whole, { status: 200 }),
    );

    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);

    expect(ranges).toEqual([`bytes=-${WITNESS_FILE_TAIL_BYTES}`]);
    expect(signatures[0]!.head!.tree_size).toBe(6);
  });

  it("refuses a from head whose root differs, path or no path", async () => {
    // The endpoint answers the right question with the real path, and names a
    // `from` head whose root is not the one our inclusion proof folds to. The
    // path folds, so the only thing that can refuse this is the check of the
    // endpoint's own head against the root already held.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([await countersignatureLine(alpha, LATER_SIZE)]);

    const { fetch } = await fakeRegistry({
      files,
      consistency: async (from, to) => ({
        log: LOG,
        from: { ...(await checkpointAt(from)), root: "a".repeat(64) },
        to: await checkpointAt(to),
        proof: await consistencyOf(leaves.slice(0, to), from),
      }),
    });
    expect(
      (await adapterWith(fetch).collect(sealedSeal(), NOW)).map(
        (entry) => entry.agent,
      ),
    ).toEqual([AGENT_ID_PREFIX + beta.publicKey]);

    // The control: the same body with that head named honestly is accepted, so
    // the path the refusal threw away was one that folds.
    const honest = await fakeRegistry({ files });
    expect(
      (await adapterWith(honest.fetch).collect(sealedSeal(), NOW)).map(
        (entry) => entry.agent,
      ),
    ).toEqual([AGENT_ID_PREFIX + alpha.publicKey, AGENT_ID_PREFIX + beta.publicKey]);
  });

  it("refuses a to head whose root differs, path or no path", async () => {
    // The other half of the same check: the `to` head the endpoint names is not
    // the countersigned head, and the path that came with it folds.
    const files = await witnessFiles();
    files[pinAlpha.url] = fileOf([await countersignatureLine(alpha, LATER_SIZE)]);

    const { fetch } = await fakeRegistry({
      files,
      consistency: async (from, to) => ({
        log: LOG,
        from: await checkpointAt(from),
        to: { ...(await checkpointAt(to)), root: "b".repeat(64) },
        proof: await consistencyOf(leaves.slice(0, to), from),
      }),
    });
    expect(
      (await adapterWith(fetch).collect(sealedSeal(), NOW)).map(
        (entry) => entry.agent,
      ),
    ).toEqual([AGENT_ID_PREFIX + beta.publicKey]);

    const honest = await fakeRegistry({ files });
    expect(
      (await adapterWith(honest.fetch).collect(sealedSeal(), NOW)).map(
        (entry) => entry.agent,
      ),
    ).toEqual([AGENT_ID_PREFIX + alpha.publicKey, AGENT_ID_PREFIX + beta.publicKey]);
  });

  it("answers nothing when the seal was never submitted", async () => {
    const { fetch, calls } = await fakeRegistry({ files: await witnessFiles() });
    const seal = sealedSeal();
    seal.registry = null;
    expect(await adapterWith(fetch).collect(seal, NOW)).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it("answers nothing when the directory cannot be read", async () => {
    const { fetch } = await fakeRegistry({
      files: await witnessFiles(),
      witnessesStatus: 503,
    });
    expect(await adapterWith(fetch).collect(sealedSeal(), NOW)).toEqual([]);
  });

  it("answers nothing when the checkpoint is not the pinned registry's", async () => {
    const other = await makeKey();
    const { fetch } = await fakeRegistry({ files: await witnessFiles() });
    const adapter = new RegistryWitnessAdapter({
      fetch,
      origin: ORIGIN,
      registryPublicKey: other.publicKey,
      log: LOG,
      label: LABEL,
      handle: HANDLE,
      credential: CREDENTIAL,
      privateKeyPkcs8: sealingKey.pkcs8,
      pin: [pinAlpha, pinBeta],
    });
    expect(await adapter.collect(sealedSeal(), NOW)).toEqual([]);
  });

  it("skips a line whose witness signature does not verify", async () => {
    const files = await witnessFiles();
    const forged = await countersignatureLine(alpha, 6);
    forged["witness_sig"] = base64urlEncode(new Uint8Array(64));
    files[pinAlpha.url] = fileOf([forged]);

    const { fetch } = await fakeRegistry({ files });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + beta.publicKey,
    ]);
  });

  it("skips a witness whose file is unreachable", async () => {
    const files = await witnessFiles();
    delete files[pinBeta.url];
    const { fetch } = await fakeRegistry({ files });
    const signatures = await adapterWith(fetch).collect(sealedSeal(), NOW);
    expect(signatures.map((entry) => entry.agent)).toEqual([
      AGENT_ID_PREFIX + alpha.publicKey,
    ]);
  });
});

describe("RegistryWitnessAdapter.heal", () => {
  it("re-resolves a record that kept the registry's seal row id", async () => {
    const { fetch, calls } = await fakeRegistry({ files: await witnessFiles() });
    const healed = await adapterWith(fetch).heal(sealWithSealRowId());

    expect(healed).not.toBeNull();
    expect(healed!.event_id).toBe(EVENT_ID);
    expect(healed!.event_hash).toBe(eventHashes[LEAF_INDEX]);
    // Everything else the record carried is kept: this corrects a reading, it
    // does not re-seal anything.
    expect(healed!.registry).toBe(ORIGIN);
    expect(healed!.handle).toBe(HANDLE);
    expect(healed!.label).toBe(LABEL);
    expect(healed!.sealed_at).toBe(NOW.toISOString());
    expect(
      calls.some((call) => call.url.includes(`/api/record/${HANDLE}`)),
    ).toBe(true);
  });

  it("answers null for a record that already names the identity event", async () => {
    const { fetch } = await fakeRegistry();
    expect(await adapterWith(fetch).heal(sealedSeal())).toBeNull();
  });

  it("answers null rather than overwriting when the record cannot be read", async () => {
    const seal = sealWithSealRowId();
    const { fetch } = await fakeRegistry({
      record: { events: "not a list" },
    });
    expect(await adapterWith(fetch).heal(seal)).toBeNull();

    const dead = (async () => {
      throw new TypeError("network down");
    }) as unknown as typeof fetch;
    expect(await adapterWith(dead).heal(seal)).toBeNull();
  });

  it("answers null when there is no registry record at all", async () => {
    const seal = sealedSeal();
    seal.registry = null;
    const { fetch, calls } = await fakeRegistry();
    expect(await adapterWith(fetch).heal(seal)).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("re-resolves a stored id whose own proof is not the stored hash", async () => {
    // A record naming an id and a hash that do not belong together is not
    // believed because it named both: the proof for the id has to *be* that
    // event, and the seal row's proof is another event entirely.
    const seal = sealedSeal();
    seal.registry = {
      ...seal.registry!,
      event_id: SEAL_ROW_ID,
      event_hash: eventHashes[LEAF_INDEX]!,
    };

    const { fetch } = await fakeRegistry({ files: await witnessFiles() });
    const healed = await adapterWith(fetch).heal(seal);
    expect(healed).not.toBeNull();
    expect(healed!.event_id).toBe(EVENT_ID);
    expect(healed!.event_hash).toBe(eventHashes[LEAF_INDEX]);

    // And nothing is countersigned against the proof that id answers with.
    const signatures = await adapterWith(fetch).collect(seal, NOW);
    expect(signatures).toHaveLength(2);
    for (const signature of signatures) {
      expect(signature.evidence!.leaf_index).toBe(LEAF_INDEX);
      expect(signature.evidence!.event_hash).toBe(eventHashes[LEAF_INDEX]);
    }
    expect((await checkWitnesses(SEAL_HASH, signatures, testContext())).ok).toBe(
      true,
    );
  });

  it("collects against the re-resolved event, never the seal row's", async () => {
    const { fetch, calls } = await fakeRegistry({ files: await witnessFiles() });
    const signatures = await adapterWith(fetch).collect(
      sealWithSealRowId(),
      NOW,
    );

    expect(signatures).toHaveLength(2);
    for (const signature of signatures) {
      expect(signature.evidence!.leaf_index).toBe(LEAF_INDEX);
      expect(signature.evidence!.event_hash).toBe(eventHashes[LEAF_INDEX]);
      // The proof the seal row id answers with is another event's, and no
      // evidence ever carries it.
      expect(signature.evidence!.event_hash).not.toBe(
        eventHashes[OTHER_LEAF_INDEX],
      );
    }
    const check = await checkWitnesses(SEAL_HASH, signatures, testContext());
    expect(check.ok).toBe(true);

    // The wrong proof was asked for once, and its answer was refused; the leaf
    // that was used came from the record.
    expect(calls.some((call) => call.url.includes(`&event=${EVENT_ID}`))).toBe(
      true,
    );
  });

  it("collects nothing when the record cannot name the event", async () => {
    const { fetch } = await fakeRegistry({
      files: await witnessFiles(),
      record: recordOf([]),
    });
    expect(await adapterWith(fetch).collect(sealWithSealRowId(), NOW)).toEqual(
      [],
    );
  });
});

/**
 * The same fix against production's own wire.
 *
 * Everything here comes out of test/fixtures/registry: the citizen record of
 * `nomankind` and the two proofs — the identity event that really anchors
 * production seal 0, and the unrelated August event the stored seal row id asks
 * for. The registry key is the pinned one, so the checkpoint signatures are
 * checked exactly as production checks them, and nothing is generated.
 */
describe("the registry's identity event (production seal 0)", () => {
  const fixture = (name: string): unknown =>
    JSON.parse(
      readFileSync(new URL(`./fixtures/registry/${name}`, import.meta.url), "utf8"),
    );

  const PRODUCTION_HANDLE = "nomankind";
  const PRODUCTION_FINGERPRINT =
    "a61ae671cdb6f7579a0decfc9ea56f3ac3c472298017c233d6108a0619c922d6";
  /** The `memory.seal` identity event that anchors it, from the record. */
  const ANCHOR_EVENT_ID = 9888;
  const ANCHOR_EVENT_HASH =
    "3eb4ad8a83b598f9625286f419288f75949c8655c1e458f87b2f0a5f8f188ab7";
  const ANCHOR_LEAF_INDEX = 9873;
  /** The registry's seal row id, which is what was stored in its place. */
  const PRODUCTION_SEAL_ROW_ID = 4281;
  const WRONG_EVENT_HASH =
    "38b5f3cb351da58a5422b54bac6791d5ca63a5596b307a47b36609a3d31235b8";

  /**
   * The head the registry answered the proof under, and the head the pinned
   * liveness witness had countersigned by the time the sweep ran.
   *
   * The first is the *earliest* checkpoint covering leaf 9873, which is what the
   * registry always answers with; the second is whatever head was current when
   * the witness last ran. The second being the larger is the ordinary case, and
   * the defect this pair reproduces: nothing could bridge from 9971 back to
   * 9874, because that proof does not exist.
   */
  const PROVED_SIZE = 9874;
  const COUNTERSIGNED_SIZE = 9971;

  /** The liveness witness (pin id 8) and its newest captured line, verbatim. */
  const LIVENESS_PIN = WITNESS_PIN.find((row) => row.id === 8)!;
  const LIVENESS_LINE = readFileSync(
    new URL(
      "./fixtures/registry/witness-line-liveness-9971.jsonl",
      import.meta.url,
    ),
    "utf8",
  );

  /** The three captured responses, and the POST the registry answers with. */
  function productionRegistry(record: unknown = fixture("record-nomankind.json")): {
    fetch: typeof fetch;
    asked: string[];
  } {
    const asked: string[] = [];
    const fetchFn = async function (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> {
      const raw = String(input);
      asked.push(raw);
      const url = new URL(raw);
      const json = (body: unknown, status = 200): Response =>
        new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        });

      if (url.pathname === "/api/seal" && init?.method === "POST") {
        // The registry names the seal row under `id` and the identity event it
        // chained under `chained`, and no identity event id anywhere.
        return json({
          ok: true,
          id: PRODUCTION_SEAL_ROW_ID,
          hash: PRODUCTION_FINGERPRINT,
          label: REGISTRY.seal_label,
          chained: ANCHOR_EVENT_HASH,
        });
      }
      if (url.pathname === `/api/record/${PRODUCTION_HANDLE}`) {
        return json(record);
      }
      if (url.pathname === "/api/proof") {
        const event = url.searchParams.get("event");
        if (event === String(ANCHOR_EVENT_ID)) {
          return json(fixture("proof-identity_events-9888.json"));
        }
        if (event === String(PRODUCTION_SEAL_ROW_ID)) {
          return json(fixture("proof-identity_events-4281.json"));
        }
        return json({ error: "not found" }, 404);
      }
      if (url.pathname === "/api/witnesses") {
        return json(fixture("witnesses.json"));
      }
      if (url.pathname === "/api/checkpoint/consistency") {
        // Only the pair that was captured, and only in the direction the
        // registry answers it in: `0 <= from <= to`.
        const pair = `${url.searchParams.get("from")}-${url.searchParams.get("to")}`;
        if (pair === `${PROVED_SIZE}-${COUNTERSIGNED_SIZE}`) {
          return json(
            fixture(
              `consistency-identity_events-${PROVED_SIZE}-${COUNTERSIGNED_SIZE}.json`,
            ),
          );
        }
        return json({ error: "from must not exceed to" }, 400);
      }
      if (raw === LIVENESS_PIN.url) {
        return new Response(LIVENESS_LINE, { status: 200 });
      }
      return new Response("not found", { status: 404 });
    } as unknown as typeof fetch;
    return { fetch: fetchFn, asked };
  }

  function productionAdapter(fetchFn: typeof fetch): RegistryWitnessAdapter {
    return new RegistryWitnessAdapter({
      fetch: fetchFn,
      handle: PRODUCTION_HANDLE,
      credential: CREDENTIAL,
      privateKeyPkcs8: sealingKey.pkcs8,
    });
  }

  /** Production seal 0, as its fingerprint says it is. */
  function productionSeal(registry: {
    event_id: number | null;
    event_hash: string | null;
  }): Seal {
    return {
      seq: 0,
      first_seq: 0,
      last_seq: 0,
      size: 1,
      root: `sha256:${"cd".repeat(32)}`,
      sealed_at: NOW.toISOString(),
      prev_hash: null,
      hash: `sha256:${PRODUCTION_FINGERPRINT}`,
      witnesses: [],
      registry: {
        registry: REGISTRY.origin,
        handle: PRODUCTION_HANDLE,
        label: REGISTRY.seal_label,
        receipt: null,
        sealed_at: NOW.toISOString(),
        ...registry,
      },
    };
  }

  it("stores the event the record names, not the seal row the response does", async () => {
    const { fetch } = productionRegistry();
    const sealed = await productionAdapter(fetch).seal(
      productionSeal({ event_id: null, event_hash: null }),
      NOW,
    );

    expect(sealed).not.toBeNull();
    expect(sealed!.event_id).toBe(ANCHOR_EVENT_ID);
    expect(sealed!.event_hash).toBe(ANCHOR_EVENT_HASH);
    expect(sealed!.event_id).not.toBe(PRODUCTION_SEAL_ROW_ID);
  });

  it("stores no id at all when the record has not listed the event", async () => {
    const record = fixture("record-nomankind.json") as {
      events: { kind: string }[];
    };
    const { fetch } = productionRegistry({
      ...record,
      events: record.events.filter((event) => event.kind !== "memory.seal"),
    });
    const sealed = await productionAdapter(fetch).seal(
      productionSeal({ event_id: null, event_hash: null }),
      NOW,
    );

    expect(sealed!.event_id).toBeNull();
    // The chained hash is still worth keeping: it is what the next run resolves
    // the id by.
    expect(sealed!.event_hash).toBe(ANCHOR_EVENT_HASH);
  });

  it("heals the stored record production really has", async () => {
    const { fetch } = productionRegistry();
    const healed = await productionAdapter(fetch).heal(
      productionSeal({ event_id: PRODUCTION_SEAL_ROW_ID, event_hash: null }),
    );

    expect(healed).not.toBeNull();
    expect(healed!.event_id).toBe(ANCHOR_EVENT_ID);
    expect(healed!.event_hash).toBe(ANCHOR_EVENT_HASH);
    // Never the event the seal row id's own proof answers with.
    expect(healed!.event_hash).not.toBe(WRONG_EVENT_HASH);
  });

  it("heals a stored record that kept the chained hash and no id", async () => {
    const { fetch } = productionRegistry();
    const healed = await productionAdapter(fetch).heal(
      productionSeal({ event_id: null, event_hash: ANCHOR_EVENT_HASH }),
    );
    expect(healed!.event_id).toBe(ANCHOR_EVENT_ID);
    expect(healed!.event_hash).toBe(ANCHOR_EVENT_HASH);
  });

  it("answers null once the stored record is the healed one", async () => {
    const { fetch, asked } = productionRegistry();
    const healed = await productionAdapter(fetch).heal(
      productionSeal({
        event_id: ANCHOR_EVENT_ID,
        event_hash: ANCHOR_EVENT_HASH,
      }),
    );
    expect(healed).toBeNull();
    // Believed on the strength of its own proof: the record is not even read.
    expect(asked.some((url) => url.includes("/api/record/"))).toBe(false);
  });

  it("heals a stored id that came with the anchoring hash beside it", async () => {
    // The pairing production would have stored had the response named an event
    // id as well: the id is the seal row's, the hash is the right event's, and
    // the proof for the id says they are not the same event.
    const { fetch } = productionRegistry();
    const healed = await productionAdapter(fetch).heal(
      productionSeal({
        event_id: PRODUCTION_SEAL_ROW_ID,
        event_hash: ANCHOR_EVENT_HASH,
      }),
    );
    expect(healed).not.toBeNull();
    expect(healed!.event_id).toBe(ANCHOR_EVENT_ID);
    expect(healed!.event_hash).toBe(ANCHOR_EVENT_HASH);
  });

  it("verifies the right event's proof against its checkpoint root", async () => {
    const proof = fixture("proof-identity_events-9888.json") as {
      event: { id: number; hash: string; leaf_index: number };
      checkpoint: { tree_size: number; root: string; sig: string; created_at: number };
      proof: string[];
    };
    expect(proof.event.id).toBe(ANCHOR_EVENT_ID);
    expect(proof.event.hash).toBe(ANCHOR_EVENT_HASH);
    expect(proof.event.leaf_index).toBe(ANCHOR_LEAF_INDEX);

    // The pinned registry key signed the head the proof was fetched against.
    expect(
      await verifyBytes(
        base64urlDecode(REGISTRY.public_key),
        registryCheckpointPayload({
          log: REGISTRY.log,
          tree_size: proof.checkpoint.tree_size,
          root: proof.checkpoint.root,
          created_at: proof.checkpoint.created_at,
        }),
        base64urlDecode(proof.checkpoint.sig),
      ),
    ).toBe(true);

    expect(
      await verifyRegistryInclusion({
        leafHash: await registryLeafHash(proof.event.hash),
        leafIndex: proof.event.leaf_index,
        treeSize: proof.checkpoint.tree_size,
        path: proof.proof,
        root: proof.checkpoint.root,
      }),
    ).toBe(true);
  });

  it("never accepts the seal row id's proof as evidence for this seal", async () => {
    const wrong = fixture("proof-identity_events-4281.json") as {
      event: { id: number; hash: string; leaf_index: number };
      checkpoint: { tree_size: number; root: string };
      proof: string[];
    };
    const right = fixture("proof-identity_events-9888.json") as {
      checkpoint: { tree_size: number; root: string };
    };

    // What the stored seal row id asks for: another citizen's August event,
    // under a head 5,606 leaves behind ours.
    expect(wrong.event.id).toBe(PRODUCTION_SEAL_ROW_ID);
    expect(wrong.event.hash).toBe(WRONG_EVENT_HASH);
    expect(wrong.event.leaf_index).toBe(4266);
    expect(wrong.checkpoint.tree_size).toBeLessThan(right.checkpoint.tree_size);

    // Its leaf folds to its own root and to no other, so no countersignature of
    // our head could ever cover it.
    expect(
      await verifyRegistryInclusion({
        leafHash: await registryLeafHash(wrong.event.hash),
        leafIndex: wrong.event.leaf_index,
        treeSize: wrong.checkpoint.tree_size,
        path: wrong.proof,
        root: right.checkpoint.root,
      }),
    ).toBe(false);

    // And the adapter, handed that record, resolves past it rather than using it.
    const { fetch } = productionRegistry();
    const seal = productionSeal({
      event_id: PRODUCTION_SEAL_ROW_ID,
      event_hash: null,
    });
    const healed = await productionAdapter(fetch).heal(seal);
    expect(healed!.event_id).toBe(ANCHOR_EVENT_ID);
  });

  it("collects the liveness witness's later head, bridged forward", async () => {
    const { fetch, asked } = productionRegistry();
    const signatures = await productionAdapter(fetch).collect(
      productionSeal({
        event_id: ANCHOR_EVENT_ID,
        event_hash: ANCHOR_EVENT_HASH,
      }),
      NOW,
    );

    // One countersignature, from the one pinned witness whose file was captured.
    expect(signatures).toHaveLength(1);
    const entry = signatures[0]!;
    expect(entry.agent).toBe(AGENT_ID_PREFIX + LIVENESS_PIN.public_key);
    expect(entry.head!.tree_size).toBe(COUNTERSIGNED_SIZE);
    expect(entry.head!.registry).toBe(REGISTRY.origin);
    expect(entry.evidence!.leaf_index).toBe(ANCHOR_LEAF_INDEX);
    expect(entry.evidence!.event_hash).toBe(ANCHOR_EVENT_HASH);
    expect(entry.evidence!.proved_at.tree_size).toBe(PROVED_SIZE);
    expect(entry.evidence!.consistency_proof.length).toBeGreaterThan(0);

    // The bridge was asked for the only way the registry answers it.
    expect(
      asked.some((url) =>
        url.includes(`from=${PROVED_SIZE}&to=${COUNTERSIGNED_SIZE}`),
      ),
    ).toBe(true);

    // And the rule accepts it against the real pin: this is the signature the
    // sweep skipped as witness_pending before the bridge could run forward.
    const pinned = pinnedWitnessesFor("production");
    const check = await checkWitnesses(`sha256:${PRODUCTION_FINGERPRINT}`, signatures, {
      witnesses: pinned.witnesses,
      maintainerOperators: new Set<string>(["nomankind"]),
      ineligibleAgents: new Set<string>(),
      registry: pinned.registry,
    });
    expect(check.ok).toBe(true);
    expect(check.ok && check.witnesses.map((witness) => witness.operator)).toEqual([
      LIVENESS_PIN.operator,
    ]);
  });
});

describe("witnessAdapterFor", () => {
  const envOf = (fields: Partial<Env>): Env =>
    ({ ENVIRONMENT: "local", ...fields }) as unknown as Env;

  it("gives local and demo the mock", () => {
    for (const environment of ["local", "demo"]) {
      const adapter = witnessAdapterFor(envOf({ ENVIRONMENT: environment }));
      expect(adapter).toBeInstanceOf(MockWitnessAdapter);
      expect(adapter.kind).toBe("mock");
    }
  });

  it("gives production nothing until all three are set", () => {
    const partials: Partial<Env>[] = [
      {},
      { SEALING_AGENT_KEY: "k" },
      { SEALING_AGENT_KEY: "k", REGISTRY_CREDENTIAL: "c" },
      { SEALING_AGENT_KEY: "k", SEALING_AGENT_HANDLE: "h" },
      { SEALING_AGENT_KEY: "", REGISTRY_CREDENTIAL: "c", SEALING_AGENT_HANDLE: "h" },
      { SEALING_AGENT_KEY: "k", REGISTRY_CREDENTIAL: "c", SEALING_AGENT_HANDLE: "" },
    ];
    for (const fields of partials) {
      const adapter = witnessAdapterFor(
        envOf({ ENVIRONMENT: "production", ...fields }),
      );
      expect(adapter).toBeInstanceOf(UnavailableWitnessAdapter);
      expect(adapter.kind).toBe("unavailable");
    }
  });

  it("gives production the registry adapter once the maintainer set them", () => {
    const adapter = witnessAdapterFor(
      envOf({
        ENVIRONMENT: "production",
        SEALING_AGENT_KEY: sealingKey.pkcs8,
        REGISTRY_CREDENTIAL: CREDENTIAL,
        SEALING_AGENT_HANDLE: HANDLE,
      }),
    );
    expect(adapter).toBeInstanceOf(RegistryWitnessAdapter);
    expect(adapter.kind).toBe("registry");
  });

  it("answers nothing at all from the unavailable adapter", async () => {
    const adapter = new UnavailableWitnessAdapter();
    expect(await adapter.seal()).toBeNull();
    expect(await adapter.collect()).toEqual([]);
  });
});

describe("sealingAgentIdFor", () => {
  const envOf = (fields: Partial<Env>): Env =>
    ({ ENVIRONMENT: "production", ...fields }) as unknown as Env;

  it("derives the agent id from the secret's public half", async () => {
    const id = await sealingAgentIdFor(envOf({ SEALING_AGENT_KEY: sealingKey.pkcs8 }));
    expect(id).toBe(AGENT_ID_PREFIX + sealingKey.publicKey);
  });

  it("answers null when the key is unset or unreadable", async () => {
    expect(await sealingAgentIdFor(envOf({}))).toBeNull();
    expect(await sealingAgentIdFor(envOf({ SEALING_AGENT_KEY: "" }))).toBeNull();
    expect(
      await sealingAgentIdFor(envOf({ SEALING_AGENT_KEY: "not a key" })),
    ).toBeNull();
  });
});
