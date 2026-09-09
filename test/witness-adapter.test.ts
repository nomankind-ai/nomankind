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
import { REGISTRY, WITNESS_PIN } from "../src/policy.js";
import {
  registryCheckpointPayload,
  registryWitnessPayload,
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

/** Our memory.seal identity event: the fourth leaf of an eight-leaf log. */
const SIZE = 8;
const LEAF_INDEX = 3;
const EVENT_ID = 103;

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
  seals?: unknown;
  /** Whether the directory endpoint answers at all. */
  witnessesStatus?: number;
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
      const answer = options.seal ?? {
        status: 200,
        body: {
          seal: { id: 7, hash: FINGERPRINT, label: LABEL },
          event: { id: EVENT_ID, hash: eventHashes[LEAF_INDEX] },
        },
      };
      return json(answer.body, answer.status);
    }

    if (url.origin === ORIGIN && url.pathname === "/api/seals") {
      return json(
        options.seals ?? {
          latest: { id: 999, hash: "ff".repeat(32), label: LABEL },
          seals: [
            { id: 12, hash: "11".repeat(32), label: LABEL },
            { id: EVENT_ID, hash: FINGERPRINT, label: LABEL },
          ],
        },
      );
    }

    if (url.origin === ORIGIN && url.pathname === "/api/witnesses") {
      const status = options.witnessesStatus ?? 200;
      if (status !== 200) return json({ error: "unavailable" }, status);
      return json({ witnesses: directory, count: directory.length });
    }

    if (url.origin === ORIGIN && url.pathname === "/api/proof") {
      return json({
        log: url.searchParams.get("log"),
        event: {
          id: Number(url.searchParams.get("event")),
          hash: eventHashes[LEAF_INDEX],
          leaf_index: LEAF_INDEX,
        },
        checkpoint: await checkpointAt(SIZE),
        proof: await pathOf(leaves, LEAF_INDEX),
      });
    }

    if (url.origin === ORIGIN && url.pathname === "/api/checkpoint/consistency") {
      const from = Number(url.searchParams.get("from"));
      const to = Number(url.searchParams.get("to"));
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
      event_hash: null,
      receipt: null,
      sealed_at: NOW.toISOString(),
    },
  };
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

  eventHashes = Array.from({ length: SIZE }, (_, index) =>
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
      seal: { id: 7, hash: FINGERPRINT, label: LABEL },
      event: { id: EVENT_ID, hash: eventHashes[LEAF_INDEX] },
    });

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

  it("resolves a 409 through the seal listing", async () => {
    const { fetch, calls } = await fakeRegistry({
      seal: { status: 409, body: { error: "already_sealed" } },
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);

    expect(sealed).not.toBeNull();
    expect(sealed!.event_id).toBe(EVENT_ID);
    // The listing names the seal row, not the chain hash, so it stays null
    // rather than being guessed at.
    expect(sealed!.event_hash).toBeNull();
    expect(sealed!.receipt).toEqual({ error: "already_sealed" });
    expect(
      calls.some((call) => call.url.includes("/api/seals?citizen=")),
    ).toBe(true);
  });

  it("resolves a 200 that names no event id the same way", async () => {
    const { fetch } = await fakeRegistry({
      seal: { status: 200, body: { seal: { hash: FINGERPRINT } } },
    });
    const sealed = await adapterWith(fetch).seal(sealedSeal(), NOW);
    expect(sealed!.event_id).toBe(EVENT_ID);
    expect(sealed!.event_hash).toBeNull();
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
