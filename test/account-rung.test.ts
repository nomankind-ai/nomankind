/**
 * The account rung, in its parts (decision D-142).
 *
 * The end-to-end proof is test/m25-account-rung-end-to-end.test.ts, where three
 * bare replies on two boards travel through the real sweep. This file is the
 * pieces that end-to-end test would not tell apart if one of them broke: what
 * each adapter answers for a comment capture and an account's creation date,
 * what the three read doors do with `min_binding`, what the delta stream's
 * filter does with the rung, what a mirror's replay makes of an upgrade, and
 * what the pages say in words.
 *
 * Nothing here reaches a network. The board is the fixture board, the doors are
 * their own parsers, and the pages are rendered from view models.
 */

import { describe, expect, it } from "vitest";

import {
  ColonyBoardAdapter,
  GitHubBoardAdapter,
  MockBoardAdapter,
  RegistryBoardAdapter,
  type BoardComment,
} from "../src/adapters/board.js";
import { bindingSatisfies } from "../src/derive.js";
import { appendEvent, type Event } from "../src/events.js";
import { operatorRows } from "../src/import.js";
import {
  BINDING_RUNGS,
  CONFIRMATION_VENUES,
  DEFAULT_DOMAIN,
  PERIMETER_ACCOUNTS,
  PERIMETER_WORD,
  POLICY,
  REGISTRY,
} from "../src/policy.js";
import { parseReadQuery } from "../src/read.js";
import { keepSyncItem, parseSyncQuery } from "../src/sync.js";
import { parseEntriesQuery } from "../src/ui/query.js";
import { renderIndependence } from "../src/ui/pages/independence.js";
import { renderOperators } from "../src/ui/pages/operators.js";
import { renderPolicy } from "../src/ui/pages/policy.js";
import type { PageContext } from "../src/ui/types.js";

const ctx: PageContext = {
  origin: "https://app.nomankind.ai",
  path: "/",
  environment: "local",
  version: "test",
} as unknown as PageContext;

const COLONY = CONFIRMATION_VENUES.find((row) => row.venue === "colony")!;
const GITHUB = CONFIRMATION_VENUES.find((row) => row.venue === "github")!;
const REGISTRY_VENUE = CONFIRMATION_VENUES.find((row) => row.venue === "1f916")!;

/** One comment, as a board hands one to the sweep. */
function comment(overrides: Partial<BoardComment> = {}): BoardComment {
  return {
    id: 4_221_001,
    thread: 1,
    handle: "field-notes",
    body: "nomankind-confirm-v1 nmk_x approve hash:abc attest:v1",
    posted_at: "2026-09-16T09:00:00.000Z",
    ...overrides,
  };
}

/**
 * A fetcher that answers one body per URL, and records which URLs were asked.
 *
 * The whole of the network in the adapter tests below: what is being checked is
 * which door the adapter knocked on and what it made of the answer, and a real
 * request would prove neither.
 */
function fetcherFor(
  bodies: Readonly<Record<string, string>>,
  asked: string[],
): typeof fetch {
  return (async (url: string) => {
    asked.push(url);
    // A fragment never reaches a server, which is what makes a permalink with
    // one a door the adapter may fetch: the bytes are the page's.
    const withoutFragment = url.split("#")[0]!;
    const body = bodies[withoutFragment];
    if (body === undefined) return new Response("no", { status: 404 });
    return new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

describe("the board adapters' two captures (D-142)", () => {
  it("answers a comment capture and a profile with a creation date on the mock", async () => {
    const board = new MockBoardAdapter({
      venue: "colony",
      binding: "profile",
      profiles: new Map([["field-notes", JSON.stringify({ bio: "hello" })]]),
      accounts: new Map([["field-notes", "2024-03-01T00:00:00.000Z"]]),
    });

    const profile = await board.profile!("field-notes");
    expect(profile).not.toBeNull();
    expect(profile!.created_at).toBe("2024-03-01T00:00:00.000Z");
    expect(profile!.url).toContain("field-notes");

    const captured = await board.comment!(comment({ id: "uuid-1" }));
    expect(captured).not.toBeNull();
    expect(captured!.url).toContain("uuid-1");
    // The fixture's default capture is the comment itself, which is what a
    // board with a per-comment door answers.
    const decoded = JSON.parse(new TextDecoder().decode(captured!.bytes)) as {
      id: string;
      body: string;
    };
    expect(decoded.id).toBe("uuid-1");
    expect(decoded.body).toContain("nomankind-confirm-v1");
    expect(board.commentReads).toEqual(["uuid-1"]);
  });

  it("answers no creation date for an account the venue says nothing about", async () => {
    const board = new MockBoardAdapter({
      venue: "colony",
      binding: "profile",
      profiles: new Map([["quiet", JSON.stringify({ bio: "hello" })]]),
    });
    // Null and never a guess: an account whose age the platform does not
    // publish is one the rung cannot be reached on.
    expect((await board.profile!("quiet"))!.created_at).toBeNull();
  });

  it("answers null for a comment the fixture names no capture for", async () => {
    const board = new MockBoardAdapter({
      venue: "colony",
      binding: "profile",
      commentCaptures: new Map([["known", "{}"]]),
    });
    expect(await board.comment!(comment({ id: "known" }))).not.toBeNull();
    // A capture that failed is null, which is what leaves the line uncounted
    // with a reason rather than counted on a guess.
    expect(await board.comment!(comment({ id: "missing" }))).toBeNull();
  });

  it("reads The Colony's created_at off the profile door it already uses", async () => {
    const asked: string[] = [];
    const board = new ColonyBoardAdapter({
      venue: COLONY,
      environment: "demo",
      fetch: fetcherFor(
        {
          [`${COLONY.origin}/api/v1/users/field-notes`]: JSON.stringify({
            username: "field-notes",
            bio: "an agent",
            created_at: "2025-01-02T03:04:05.000Z",
          }),
        },
        asked,
      ),
    });
    const profile = await board.profile!("field-notes");
    expect(profile!.created_at).toBe("2025-01-02T03:04:05.000Z");
    // One door and one read: the creation date came back with the bytes the
    // binding is read out of, so there is no second fetch to make.
    expect(asked).toEqual([`${COLONY.origin}/api/v1/users/field-notes`]);
  });

  it("captures a Colony comment at the thread's permalink, naming the comment", async () => {
    const asked: string[] = [];
    const thread = "09ed63ba-438a-41e8-b352-f065b376106e";
    const door = `${COLONY.origin}/api/v1/posts/${thread}/context`;
    const board = new ColonyBoardAdapter({
      venue: COLONY,
      environment: "demo",
      fetch: fetcherFor({ [door]: JSON.stringify({ comments: [] }) }, asked),
    });
    const captured = await board.comment!(
      comment({ id: "uuid-9", thread }),
    );
    // The Colony publishes no per-comment door, so the capture is the thread's
    // own answer with the comment named in the fragment.
    expect(captured!.url).toBe(`${door}#comment-uuid-9`);
    expect(asked[0]).toBe(`${door}#comment-uuid-9`);
  });

  it("captures a GitHub comment at its own door, which that platform has", async () => {
    const asked: string[] = [];
    const door = `${GITHUB.origin}/repos/nomankind-ai/bootstrap/issues/comments/3311001`;
    const board = new GitHubBoardAdapter({
      venue: GITHUB,
      environment: "demo",
      fetch: fetcherFor({ [door]: JSON.stringify({ id: 3311001 }) }, asked),
    });
    const captured = await board.comment!(comment({ id: 3_311_001 }));
    // One comment, on its own: the same bytes whatever anybody writes on the
    // issue afterwards, which is what this rung should seal where it can.
    expect(captured!.url).toBe(door);
    expect(asked).toEqual([door]);
  });

  it("reads GitHub's created_at off the user door", async () => {
    const asked: string[] = [];
    const board = new GitHubBoardAdapter({
      venue: GITHUB,
      environment: "demo",
      fetch: fetcherFor(
        {
          [`${GITHUB.origin}/users/field-notes`]: JSON.stringify({
            login: "field-notes",
            type: "User",
            bio: "an agent",
            created_at: "2019-07-04T00:00:00Z",
          }),
        },
        asked,
      ),
    });
    expect((await board.profile!("field-notes"))!.created_at).toBe(
      "2019-07-04T00:00:00.000Z",
    );
  });

  it("reads a 1F916 citizen's registration off the record's oldest key-bind", async () => {
    const asked: string[] = [];
    const door = `${REGISTRY.origin}/api/record/field-notes`;
    const board = new RegistryBoardAdapter({
      venue: REGISTRY_VENUE,
      environment: "demo",
      fetch: fetcherFor(
        {
          [door]: JSON.stringify({
            citizen: { public_key: "k", created_at: 1_800_000_000_000 },
            events: [
              // Out of order on purpose: the oldest bind is the registration,
              // and a later one is a later key.
              { id: 9, kind: "identity.key_bind", created_at: 1_760_000_000_000 },
              { id: 2, kind: "identity.key_bind", created_at: 1_700_000_000_000 },
              { id: 5, kind: "memory.seal", created_at: 1_690_000_000_000 },
            ],
          }),
        },
        asked,
      ),
    });
    const profile = await board.profile!("field-notes");
    expect(profile!.url).toBe(door);
    expect(profile!.created_at).toBe(
      new Date(1_700_000_000_000).toISOString(),
    );
  });
});

describe("min_binding on the three doors (D-142)", () => {
  it("is a floor and not an exact value", () => {
    // `BINDING_RUNGS` is weakest first, so key admits key and refuses account.
    expect(BINDING_RUNGS).toEqual(["account", "key"]);
    expect(bindingSatisfies("key", "key")).toBe(true);
    expect(bindingSatisfies("account", "key")).toBe(false);
    expect(bindingSatisfies("account", "account")).toBe(true);
    expect(bindingSatisfies("key", "account")).toBe(true);
    // A null demand is no demand; a null rung fails any demand there is.
    expect(bindingSatisfies("account", null)).toBe(true);
    expect(bindingSatisfies(null, null)).toBe(true);
    expect(bindingSatisfies(null, "account")).toBe(false);
  });

  it("is taken and refused by the read door", () => {
    const ok = parseReadQuery(
      new URLSearchParams("subject=a&category=pricing&min_binding=key"),
    );
    expect(ok.ok).toBe(true);
    expect(ok.ok && ok.query.by === "subject" && ok.query.min_binding).toBe(
      "key",
    );
    const bad = parseReadQuery(
      new URLSearchParams("subject=a&category=pricing&min_binding=registry"),
    );
    expect(bad.ok).toBe(false);
    expect(!bad.ok && bad.reason).toBe("bad_min_binding");
    // Absent is no demand, and reads as null rather than as the weakest rung.
    const bare = parseReadQuery(
      new URLSearchParams("subject=a&category=pricing"),
    );
    expect(bare.ok && bare.query.by === "subject" && bare.query.min_binding).toBe(
      null,
    );
  });

  it("is taken and refused by the sync door", () => {
    const ok = parseSyncQuery(new URLSearchParams("min_binding=account"));
    expect(ok.ok && ok.query.min_binding).toBe("account");
    const bad = parseSyncQuery(new URLSearchParams("min_binding=profile"));
    expect(!bad.ok && bad.refusal).toBe("bad_min_binding");
    // Twice is its own refusal, exactly as min_class is.
    const twice = parseSyncQuery(
      new URLSearchParams("min_binding=key&min_binding=account"),
    );
    expect(!twice.ok && twice.refusal).toBe("bad_min_binding");
  });

  it("is taken and refused by the entries listing", () => {
    const ok = parseEntriesQuery(new URLSearchParams("min_binding=key"));
    expect(ok.ok && ok.filter.min_binding).toBe("key");
    const bad = parseEntriesQuery(new URLSearchParams("min_binding=account2"));
    expect(!bad.ok && bad.reason).toBe("bad_min_binding");
    // An empty value is a refusal and not an absence, like every other chip.
    const empty = parseEntriesQuery(new URLSearchParams("min_binding="));
    expect(empty.ok).toBe(false);
  });

  it("narrows the delta stream by the rung, and never an unlearn", () => {
    const state = (binding: "account" | "key" | null) => ({
      status: "verified" as const,
      effective_tier: "stated" as const,
      verification_binding: binding,
    });
    const query = parseSyncQuery(new URLSearchParams("min_binding=key"));
    expect(query.ok).toBe(true);
    if (!query.ok) return;

    expect(keepSyncItem("entry", state("key"), query.query)).toBe(true);
    expect(keepSyncItem("entry", state("account"), query.query)).toBe(false);
    // A row stored before the decision carries no rung at all, which fails a
    // demand a trainer actually made.
    expect(keepSyncItem("entry", state(null), query.query)).toBe(false);
    // An unlearn is never filtered: a trainer that ingested a fact must be told
    // it was overturned whatever it asked for.
    expect(keepSyncItem("unlearn", state("account"), query.query)).toBe(true);
    expect(keepSyncItem("event", null, query.query)).toBe(true);
  });
});

describe("a mirror's replay of an upgrade (D-142)", () => {
  it("folds community_operator_bound onto the operator it names", async () => {
    let events: Event[] = [];
    const add = async (
      type: "community_operator_registered" | "community_operator_bound",
      payload: Record<string, unknown>,
      at: string,
    ): Promise<void> => {
      events = await appendEvent(events, {
        at,
        type,
        entry_id: null,
        payload: payload as never,
      });
    };

    await add(
      "community_operator_registered",
      {
        operator: "colony:field-notes",
        venue: "colony",
        handle: "field-notes",
        agent: "colony:field-notes",
        binding: {
          kind: "account",
          venue: "colony",
          handle: "field-notes",
          comment_url: "https://thecolony.ai/c/1",
          comment_capture_hash: "sha256:aa",
          profile_url: "https://thecolony.ai/api/v1/users/field-notes",
          profile_capture_hash: "sha256:bb",
          account_created_at: "2024-01-01T00:00:00.000Z",
        },
        attestation: { version: "v1", domain: "ai-models" },
        fingerprint: "sha256:cc",
        registry_event_id: null,
      },
      "2026-09-16T09:00:00.000Z",
    );
    await add(
      "community_operator_bound",
      {
        operator: "colony:field-notes",
        agent: "1F916:the-key",
        binding: {
          kind: "profile",
          url: "https://thecolony.ai/api/v1/users/field-notes",
          capture_hash: "sha256:dd",
          public_key: "the-key",
        },
        capture_hash: "sha256:dd",
        fingerprint: "sha256:ee",
      },
      "2026-09-17T09:00:00.000Z",
    );

    const head = events[events.length - 1]!.seq;
    // The mirror's own operators.json, agreeing with the log: the fold is
    // compared against it, and a file that named the registration's bare
    // account after an upgrade is exactly the disagreement this check is for.
    const rows = operatorRows(
      events,
      [
        {
          operator: "colony:field-notes",
          kind: "community",
          maintainer: false,
          provider: false,
          trusted: false,
          domains: ["ai-models"],
          agents: ["colony:field-notes", "1F916:the-key"],
        } as never,
      ],
      head,
    );
    const row = rows.find((each) => each.record.id === "colony:field-notes")!;
    expect(row).toBeDefined();
    // The row a mirror shows names the binding the log ended on, not the one it
    // started on: a mirror that folded only the registration would show every
    // upgraded operator still standing on a bare account.
    const details = row.record.details as Record<string, unknown>;
    const binding = details["binding"] as Record<string, unknown>;
    expect(binding["kind"]).toBe("profile");
    expect(details["agent"]).toBe("1F916:the-key");
    // Additive: the key the upgrade named is bound beside the id the
    // registration minted, and the registration's own position is untouched.
    expect(row.agents.map((each) => each.agentId)).toEqual([
      "colony:field-notes",
      "1F916:the-key",
    ]);
    expect(row.record.registeredSeq).toBe(events[0]!.seq);
  });
});

describe("the pages' words about the rung (D-142)", () => {
  it("groups the five new constants under Bindings on the policy page", () => {
    const html = renderPolicy(ctx, POLICY);
    expect(html).toContain("Bindings");
    expect(html).toContain("BINDING_RUNGS");
    expect(html).toContain("ACCOUNT_BINDING_TIERS");
    expect(html).toContain("ACCOUNT_BINDING_SUNSET");
    expect(html).toContain("PERIMETER_WORD");
    expect(html).toContain("PERIMETER_ACCOUNTS");
    expect(html).toContain(POLICY.ACCOUNT_BINDING_SUNSET);
  });

  it("lists the perimeter accounts as the disclosed perimeter", () => {
    const html = renderIndependence(ctx, {
      report: {
        validator_set: [],
        validator_perimeters: {},
        witness_set: [],
        intersection: [],
        covered_object: {},
        derived_from: {},
        external_witness_outside_validator_and_subject_provider_control: true,
        claim: "",
        seal_seq: null,
      },
    } as never);
    expect(html).toContain("Perimeter accounts");
    for (const operator of PERIMETER_ACCOUNTS) {
      expect(html).toContain(operator);
    }
    expect(html).toContain(PERIMETER_WORD);
    // Disclosed rather than merely uncounted, which is the whole point.
    expect(html).toContain("nomankind's own accounts on the boards");
    expect(html).toContain("at any rung");
  });

  it("says how strongly each community operator is bound on the directory", () => {
    const html = renderOperators(ctx, {
      rows: [
        {
          id: "colony:field-notes",
          kind: "community",
          community: {
            venue: "colony",
            handle: "field-notes",
            agent: "colony:field-notes",
            binding: {
              kind: "account",
              venue: "colony",
              handle: "field-notes",
              comment_url: "https://thecolony.ai/c/1",
              comment_capture_hash: "sha256:aa",
              profile_url: "https://thecolony.ai/u/field-notes",
              profile_capture_hash: "sha256:bb",
              account_created_at: "2024-01-01T00:00:00.000Z",
            },
          },
          maintainer: false,
          provider: false,
          trusted: false,
          trustedSeq: null,
          registeredSeq: 2,
          agents: 1,
          domainSlugs: [DEFAULT_DOMAIN],
          validations: 1,
          overturned: 0,
          standing: null,
          counts: null,
          tier: "probation",
          cosigners: 0,
          perimeter: null,
        },
      ],
      bareKeys: null,
    });
    // The word `community` no longer says how strongly, so the row says it.
    expect(html).toContain("account-bound");
    expect(html).toContain("How strongly a community operator is bound");
  });
});
