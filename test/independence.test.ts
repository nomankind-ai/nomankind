/**
 * Independence made visible (decision D-121).
 *
 * Two readers of the 1F916 board asked one question between them: which set of
 * keys validates this record, which set countersigns its seals, and do they
 * overlap — with the object each signature covers spelled out in literal field
 * names. The page and its JSON twin are the answer, and what is pinned here is
 * that the answer is the log's and not the page's.
 *
 * The fixture is the Plan's own done-when: five registered operators and the
 * three pinned witnesses of src/policy.ts. On it the page lists five, three, an
 * empty intersection and the four covered objects; the flag is true while a
 * pinned witness outside the set has a countersignature the newest seal counted
 * and false when none has; and binding a pinned witness's key to a registered
 * operator — the one overlap the log can actually see — flips the claim from
 * external independence to a disclosed shared perimeter, without hiding a
 * thing.
 *
 * The last two are about cost and about cache. A view of this page must issue
 * no scan over the events table, asserted against the SQL the render actually
 * prepares (the wrapper test/cosign.test.ts uses, because it is the same
 * promise). And the JSON twin is cached beside the page rather than instead of
 * it, which is the rule every negotiated path in this system holds.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  CLAIM_EXTERNAL,
  CLAIM_NONE_COUNTED,
  CLAIM_SHARED_PERIMETER,
  CLAIM_SINGLE_PERIMETER,
  witnessAgentId,
} from "../src/independence.js";
import { WITNESS_PIN } from "../src/policy.js";
import type { Seal } from "../src/seal.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import {
  putAgent,
  putOperator,
  putOperatorDomain,
  putSeal,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type CacheLike } from "../src/worker/index.js";
import { handlePages } from "../src/worker/pages.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-14T00:00:00.000Z");
const AT = NOW.toISOString();
const ORIGIN = "https://app.nomankind.ai";

/** The five operators the done-when asks for: trusted, untrusted, maintainer. */
const OPERATORS = [
  { id: "alpha.example", trusted: true, maintainer: false, provider: false },
  { id: "beta.example", trusted: true, maintainer: false, provider: false },
  { id: "gamma.example", trusted: true, maintainer: false, provider: false },
  { id: "delta.example", trusted: false, maintainer: false, provider: false },
  { id: "nomankind.ai", trusted: false, maintainer: true, provider: false },
] as const;

/** The perimeter the maintainer disclosed for one of them (decision D-128). */
const PERIMETER = "nomankind";

/** The two witnesses whose countersignatures the newest seal carries. */
const WITH_HEAD = WITNESS_PIN[0]!;
const DIRECT = WITNESS_PIN[1]!;

const HEAD = Object.freeze({
  registry: "https://1f916.ai",
  log: "identity_events",
  tree_size: 9134,
  root: "a".repeat(64),
  created_at: 1789000000,
  registry_sig: "c2ln",
});

function sealWith(witnesses: Seal["witnesses"]): Seal {
  return {
    seq: 4,
    first_seq: 1,
    last_seq: 9,
    size: 9,
    root: `sha256:${"b".repeat(64)}`,
    sealed_at: AT,
    prev_hash: null,
    hash: `sha256:${"c".repeat(64)}`,
    witnesses,
    registry: null,
  };
}

function envOf(on: D1Like): Env {
  return {
    DB: on,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}

/** A database that remembers every statement a render prepared. */
function watching(db: D1Like): { db: D1Like; sql: () => string[] } {
  const seen: string[] = [];
  const wrapped: D1Like = {
    prepare(sql: string): D1LikeStatement {
      seen.push(sql);
      return db.prepare(sql);
    },
    batch: (statements) => db.batch(statements),
    exec: (sql) => db.exec(sql),
  };
  return { db: wrapped, sql: () => seen };
}

/** One request through the browsing route, as a browser or as an agent. */
async function ask(
  path: string,
  on: D1Like,
  accept: string,
  method = "GET",
): Promise<Response> {
  const response = await handlePages(
    new Request(`${ORIGIN}${path}`, { method, headers: { accept } }),
    envOf(on),
    { now: NOW },
  );
  expect(response).not.toBeNull();
  return response!;
}

const page = (path: string, on: D1Like): Promise<Response> =>
  ask(path, on, "text/html");

/**
 * One page with its whitespace collapsed.
 *
 * A sentence a template wrapped over three lines is the same sentence, and a
 * test that pinned the line breaks would fail the next time a formatter moved
 * one. What is pinned here is the words.
 */
function flat(markup: string): string {
  return markup.replace(/\s+/g, " ");
}

const object = (path: string, on: D1Like): Promise<Response> =>
  ask(path, on, "application/json");

/** The report as the JSON twin answers it. */
async function report(on: D1Like): Promise<Record<string, unknown>> {
  const response = await object("/independence", on);
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toBe("application/json");
  return (await response.json()) as Record<string, unknown>;
}

let store: TestDatabase;
let db: D1Like;

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;

  let seq = 1;
  for (const operator of OPERATORS) {
    await putOperator(db, {
      id: operator.id,
      kind: "domain",
      maintainer: operator.maintainer,
      provider: operator.provider,
      registeredSeq: seq,
      details: operator.trusted
        ? {
            trusted: true,
            trusted_seq: seq,
            // Decision D-128: one of the three trusted operators was named
            // inside a disclosed perimeter and the other two were not, so the
            // grouping is a real row here and the claim is still the external
            // one -- a set that is only partly inside a perimeter is not one
            // disclosed grouping.
            ...(operator.id === "alpha.example" ? { perimeter: PERIMETER } : {}),
          }
        : { trusted: false },
    });
    await putOperatorDomain(db, {
      operator: operator.id,
      domain: "ai-ecosystem",
      seq: seq,
      attestation: null,
    });
    seq += 1;
  }
  // One operator attested in a second domain, so the domains column is a list
  // read from the log rather than one name per row by construction.
  await putOperatorDomain(db, {
    operator: "alpha.example",
    domain: "ai-safety",
    seq: seq,
    attestation: null,
  });

  // The newest seal, countersigned by two of the three pinned witnesses: one in
  // the registry form, which carries the head it covered, and one in the direct
  // form, which does not.
  await putSeal(
    db,
    sealWith([
      {
        agent: witnessAgentId(WITH_HEAD.public_key),
        signature: "c2lnbmF0dXJl",
        head: { ...HEAD },
      },
      { agent: witnessAgentId(DIRECT.public_key), signature: "c2lnbmF0dXJl" },
    ]),
  );
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the page", () => {
  it("lists both sets, the empty intersection and the four covered objects", async () => {
    const html = await (await page("/independence", db)).text();

    for (const operator of OPERATORS) expect(html).toContain(operator.id);
    expect(html).toContain(`${OPERATORS.length} operators`);
    expect(html).toContain(`${WITNESS_PIN.length} pinned witnesses`);
    for (const pin of WITNESS_PIN) {
      expect(html).toContain(pin.operator);
      expect(html).toContain(pin.public_key);
    }

    // Empty by rule, and said in words rather than shown as a blank table.
    expect(html).toContain(
      "no pinned witness is a registered operator of this record",
    );

    for (const kind of [
      "validation",
      "seal",
      "witness_countersignature",
      "anchor",
    ]) {
      expect(html).toContain(kind);
    }
    // What the countersignature is over, which is the thing the board asked.
    expect(html).toContain("tree_size");
    expect(html).toContain("Never the event and never the seal");
  }, 120_000);

  it("says what the comparison is and that it is not airtight", async () => {
    const html = await (await page("/independence", db)).text();
    const words = flat(html);
    expect(words).toContain(
      "a witness whose key is bound as a registered operator's agent",
    );
    expect(words).toContain("the exclusion is honest, not airtight");
    expect(words).toContain(
      "the frames a measurement was taken in are not recorded at all",
    );
  }, 120_000);

  it("shows the head each live witness countersigned, and says when none is stored", async () => {
    const html = await (await page("/independence", db)).text();
    expect(html).toContain(String(HEAD.tree_size));
    expect(html).toContain(HEAD.root);
    expect(html).toContain("no head stored (direct form)");
    // The third pin has countersigned nothing the newest seal carries.
    expect(html).toContain("none on the newest seal");
  }, 120_000);

  it("claims external independent confirmation while the sets are apart", async () => {
    const html = await (await page("/independence", db)).text();
    expect(html).toContain(CLAIM_EXTERNAL);
    expect(html).not.toContain(`<p class="lede">${CLAIM_SHARED_PERIMETER}</p>`);
  }, 120_000);
});

describe("the JSON twin", () => {
  it("uses the field names the question was asked in", async () => {
    const body = await report(db);
    expect(Object.keys(body)).toEqual([
      "validator_set",
      "validator_perimeters",
      "witness_set",
      "intersection",
      "covered_object",
      "derived_from",
      "external_witness_outside_validator_and_subject_provider_control",
      "claim",
      "seal_seq",
    ]);
  }, 120_000);

  it("carries every registered operator with its domains", async () => {
    const body = await report(db);
    const validators = body["validator_set"] as Record<string, unknown>[];
    expect(validators).toHaveLength(OPERATORS.length);
    expect(validators.map((each) => each["operator"])).toEqual(
      [...OPERATORS].map((each) => each.id).sort(),
    );
    const alpha = validators.find(
      (each) => each["operator"] === "alpha.example",
    )!;
    expect(alpha["domains"]).toEqual(["ai-ecosystem", "ai-safety"]);
    expect(alpha["trusted"]).toBe(true);
    // Trusted or not, because the pool is not the set.
    const delta = validators.find(
      (each) => each["operator"] === "delta.example",
    )!;
    expect(delta["trusted"]).toBe(false);
  }, 120_000);

  it("carries the pinned witnesses by id, handle, key and head", async () => {
    const body = await report(db);
    const witnesses = body["witness_set"] as Record<string, unknown>[];
    expect(witnesses.map((each) => each["id"])).toEqual(
      WITNESS_PIN.map((pin) => pin.id),
    );
    expect(witnesses.map((each) => each["operator"])).toEqual(
      WITNESS_PIN.map((pin) => pin.operator),
    );
    expect(witnesses.map((each) => each["public_key"])).toEqual(
      WITNESS_PIN.map((pin) => pin.public_key),
    );
    const first = witnesses[0]!;
    expect(first["counted"]).toBe(true);
    expect(first["head"]).toEqual({
      tree_size: HEAD.tree_size,
      root: HEAD.root,
    });
    // The direct form signs the seal hash, so there is no head to show.
    expect(witnesses[1]!["counted"]).toBe(true);
    expect(witnesses[1]!["head"]).toBeNull();
    expect(witnesses[2]!["counted"]).toBe(false);
  }, 120_000);

  it("has an empty intersection on the fixture registry, and the flag true", async () => {
    const body = await report(db);
    expect(body["intersection"]).toEqual([]);
    expect(
      body["external_witness_outside_validator_and_subject_provider_control"],
    ).toBe(true);
    expect(body["claim"]).toBe(CLAIM_EXTERNAL);
    expect(body["seal_seq"]).toBe(4);
  }, 120_000);

  it("names the object every kind of signature covers", async () => {
    const body = await report(db);
    const covered = body["covered_object"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(Object.keys(covered)).toEqual([
      "validation",
      "seal",
      "witness_countersignature",
      "anchor",
    ]);
    expect(covered["witness_countersignature"]!["covers"]).toBe(
      "a registry head",
    );
    expect(covered["witness_countersignature"]!["fields"]).toContain("tree_size");
    expect(covered["witness_countersignature"]!["fields"]).toContain("root");
    expect(covered["seal"]!["covers"]).toBe("a batch of events");
    expect(covered["validation"]!["covers"]).toBe("the entry's record");
    expect(covered["anchor"]!["covers"]).toBe("a day's seal roots");
  }, 120_000);
});

describe("a log with nothing countersigned", () => {
  let empty: TestDatabase;

  beforeAll(async () => {
    empty = await openTestDatabase();
    await putOperator(empty.db, {
      id: "alpha.example",
      kind: "domain",
      maintainer: false,
      provider: false,
      registeredSeq: 1,
      details: { trusted: true, trusted_seq: 1 },
    });
    await putSeal(empty.db, sealWith([]));
  }, 120_000);

  afterAll(async () => {
    await empty?.dispose();
  });

  it("says so rather than borrowing the claim", async () => {
    const body = await report(empty.db);
    expect(
      body["external_witness_outside_validator_and_subject_provider_control"],
    ).toBe(false);
    expect(body["claim"]).toBe(CLAIM_NONE_COUNTED);
    expect(body["intersection"]).toEqual([]);
    const html = await (await page("/independence", empty.db)).text();
    expect(html).toContain(CLAIM_NONE_COUNTED);
  }, 120_000);
});

describe("a pinned witness bound to a registered operator", () => {
  let shared: TestDatabase;

  beforeAll(async () => {
    shared = await openTestDatabase();
    await putOperator(shared.db, {
      id: "alpha.example",
      kind: "domain",
      maintainer: false,
      provider: false,
      registeredSeq: 1,
      details: { trusted: true, trusted_seq: 1 },
    });
    // The one overlap the log can actually see: the witness's own key, bound as
    // an agent of a registered operator.
    await putAgent(shared.db, {
      agentId: witnessAgentId(WITH_HEAD.public_key),
      operatorId: "alpha.example",
      registeredSeq: 2,
    });
    await putSeal(
      shared.db,
      sealWith([
        {
          agent: witnessAgentId(WITH_HEAD.public_key),
          signature: "c2lnbmF0dXJl",
          head: { ...HEAD },
        },
      ]),
    );
  }, 120_000);

  afterAll(async () => {
    await shared?.dispose();
  });

  it("publishes the overlap and flips the claim", async () => {
    const body = await report(shared.db);
    expect(body["intersection"]).toEqual([
      {
        witness: WITH_HEAD.operator,
        agent: witnessAgentId(WITH_HEAD.public_key),
        operator: "alpha.example",
        matched: "agent_bound_to_operator",
      },
    ]);
    // The only witness that countersigned is inside the set, so there is no
    // external confirmation to claim.
    expect(
      body["external_witness_outside_validator_and_subject_provider_control"],
    ).toBe(false);
    expect(body["claim"]).toBe(CLAIM_SHARED_PERIMETER);

    const html = await (await page("/independence", shared.db)).text();
    expect(html).toContain(CLAIM_SHARED_PERIMETER);
    expect(html).toContain("agent_bound_to_operator");
  }, 120_000);
});

describe("what a view costs", () => {
  it("never asks the events table for any of it", async () => {
    const { db: watched, sql } = watching(db);
    await page("/independence", watched);
    const scans = sql().filter((statement) => statement.includes("FROM events"));
    expect(scans).toEqual([]);
    // And the whole page is a handful of statements: one page of operators, one
    // grouped read of their domains, the newest seal, and one lookup per pin.
    expect(sql().length).toBeLessThanOrEqual(3 + WITNESS_PIN.length);
  }, 120_000);

  it("reads the newest seal by its own position and not by a walk", async () => {
    const { db: watched, sql } = watching(db);
    await object("/independence", watched);
    const seals = sql().filter((statement) => statement.includes("FROM seals"));
    expect(seals).toHaveLength(1);
    expect(seals[0]).toContain("ORDER BY seq DESC");
  }, 120_000);
});

describe("the doors around it", () => {
  it("refuses a write with the handlers' own envelope", async () => {
    const response = await ask("/independence", db, "text/html", "POST");
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, HEAD");
    expect(await response.json()).toEqual({ error: "method_not_allowed" });
  }, 120_000);

  it("is on the docs hub, the policy page and the operators directory", async () => {
    for (const path of ["/docs", "/policy", "/operators"]) {
      const html = await (await page(path, db)).text();
      expect([path, html.includes(`href="/independence"`)]).toEqual([
        path,
        true,
      ]);
    }
  }, 120_000);

  it("says the bar on the policy page, in the paper's words", async () => {
    const html = await (await page("/policy", db)).text();
    expect(flat(html)).toContain(
      "no pinned witness may be an operator of the record or under the control of one",
    );
  }, 120_000);

  it("carries the clause in the paper, marked as a change since v1.6", () => {
    const whitepaper = readFileSync(
      fileURLToPath(new URL("../paper/WHITEPAPER.md", import.meta.url)),
      "utf8",
    );
    // In the Limitations paragraph this bar belongs to, and nowhere else: a
    // clause about the witness set stated somewhere a reader of that paragraph
    // never reaches is a clause nobody was told.
    const limitation = whitepaper.indexOf("*The identity layer is young.*");
    const clause = whitepaper.indexOf(
      "[Spec change 2026-09-14, D-121] No pinned witness may be an operator of the record or under the control of one either",
    );
    expect(limitation).toBeGreaterThan(-1);
    expect(clause).toBeGreaterThan(limitation);
    expect(whitepaper).toContain(
      "a witness set drawn from the validators is the failure a witness set exists to catch",
    );
    // And the marker is what says "since v1.6": the paper is v1.8 now, and the
    // dated spec-change note is what carries the history rather than the
    // version line.
    expect(whitepaper).toContain("*This is v1.8.");
  });

  it("is a documentation page, so Docs stays the active nav item", async () => {
    const html = await (await page("/independence", db)).text();
    expect(html).toContain(`<a class="nav nav-active" href="/docs">Docs</a>`);
  }, 120_000);
});

/** A cache the way the router's is used: keyed by request URL, bytes and headers. */
class TestCache implements CacheLike {
  readonly held = new Map<string, { body: string; headers: Headers }>();

  async match(request: Request): Promise<Response | undefined> {
    const found = this.held.get(request.url);
    if (found === undefined) return undefined;
    return new Response(found.body, { status: 200, headers: found.headers });
  }

  async put(request: Request, response: Response): Promise<void> {
    this.held.set(request.url, {
      body: await response.text(),
      headers: new Headers(response.headers),
    });
  }
}

describe("perimeters and derived_from (D-128, D-132)", () => {
  it("groups the validator set by the word each naming disclosed", async () => {
    const body = await report(db);
    expect(body["validator_perimeters"]).toEqual({
      [PERIMETER]: ["alpha.example"],
    });
    const validators = body["validator_set"] as Record<string, unknown>[];
    const alpha = validators.find((each) => each["operator"] === "alpha.example")!;
    expect(alpha["perimeter"]).toBe(PERIMETER);
    // Every other operator was named with no grouping, which is null and never
    // a group of one.
    for (const each of validators) {
      if (each["operator"] === "alpha.example") continue;
      expect(each["perimeter"]).toBeNull();
    }
  }, 120_000);

  it("keeps the external claim while only part of the set is inside one", async () => {
    const body = await report(db);
    expect(body["claim"]).toBe(CLAIM_EXTERNAL);
  }, 120_000);

  it("shows the perimeter on the page, in the table and in the column", async () => {
    const words = flat(await (await page("/independence", db)).text());
    expect(words).toContain("Validator perimeters");
    expect(words).toContain("what the maintainer disclosed at each naming");
    expect(words).toContain("1 of 5");
    expect(words).toContain("It is never a permission");
  }, 120_000);

  it("names the rows every set is computed from, and links the command", async () => {
    const body = await report(db);
    const derived = body["derived_from"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(Object.keys(derived)).toContain("validator_set");
    expect(derived["witness_set"]!["rows"]).toEqual(["WITNESS_PIN"]);
    expect(derived["intersection"]!["rows"]).toEqual([
      "agent_bound_to_operator",
      "handle_is_operator_id",
    ]);

    const words = flat(await (await page("/independence", db)).text());
    expect(words).toContain("Derived from");
    expect(words).toContain("the published rows behind every set above");
    expect(words).toContain("npm run independence -- &lt;mirror-dir&gt;");
    expect(words).toContain("--compare &lt;served json&gt;");
    // The seal position is the one field the two may disagree on, said here
    // rather than discovered by whoever runs it.
    expect(words).toContain("the seal position is the one field");
  }, 120_000);

  it("works the demo's false-flag case through, on the page", async () => {
    const words = flat(await (await page("/independence", db)).text());
    expect(words).toContain("the demo counts no pinned witness at all");
    expect(words).toContain("counted false");
    expect(words).toContain("head null");
    expect(words).toContain("The rule did not move; the log did.");
  }, 120_000);

  it("keeps the two claims apart in words", async () => {
    const words = flat(await (await page("/independence", db)).text());
    expect(words).toContain(CLAIM_SINGLE_PERIMETER);
    expect(words).toContain(
      "says nothing about who judged the facts underneath it",
    );
  }, 120_000);
});

describe("the edge holds both twins apart", () => {
  it("never lets the JSON twin collide with the page", async () => {
    const cache = new TestCache();
    const send = (accept: string): Promise<Response> =>
      handleRequest(
        new Request(`${ORIGIN}/independence`, { headers: { accept } }),
        envOf(db),
        { now: NOW, cache },
      );

    const html = await send("text/html");
    expect(html.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(html.headers.get("vary")).toBe("Accept");

    const json = await send("application/json");
    expect(json.headers.get("content-type")).toBe("application/json");
    expect(json.headers.get("vary")).toBe("Accept");
    expect(json.headers.get("cache-control")).toContain("max-age=");
    expect(cache.held.size).toBe(2);

    // And the second reader of each gets their own document back.
    expect((await send("text/html")).headers.get("content-type")).toBe(
      "text/html; charset=utf-8",
    );
    const again = await send("application/json");
    expect(again.headers.get("content-type")).toBe("application/json");
    expect((await again.json()) as Record<string, unknown>).toHaveProperty(
      "witness_set",
    );
  }, 120_000);
});
