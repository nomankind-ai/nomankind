/**
 * M25e, the first half: the disclosed perimeter and the bootstrap label
 * (decision D-128), and D-132's `derived_from` and offline recomputation
 * beside them.
 *
 * Section 11's genesis is "a bootstrap exception to the earned-record rule,
 * stated as such". These are the two places the record states it in a fact
 * rather than in a rule: the perimeter the maintainer discloses at the moment
 * it names a founding operator, sealed into the naming event so anyone can
 * fold it back out; and the label an entry carries while every validator its
 * decision counted sat inside one such perimeter — which clears the moment
 * somebody outside looks, including through a door that does not exist yet.
 *
 * The public-confirmation seam is tested with a hand-built event object whose
 * type src/events.ts does not know, which is exactly the shape builder C's
 * door will seal: the point of the test is that the fold tolerates it today
 * and reads it correctly the day it lands.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import {
  bootstrapLabelFor,
  deriveEntry,
  operatorPerimetersAt,
  PUBLIC_CONFIRMATION_EVENT,
} from "../src/derive.js";
import type { ApproverRecord, Event, EventType } from "../src/events.js";
import {
  CLAIM_EXTERNAL,
  CLAIM_NONE_COUNTED,
  CLAIM_SHARED_PERIMETER,
  CLAIM_SINGLE_PERIMETER,
  claimFor,
  DERIVED_FROM,
  independenceReport,
  singleValidatorPerimeter,
  validatorPerimeters,
  witnessAgentId,
  type ValidatorEntry,
} from "../src/independence.js";
import { WITNESS_PIN } from "../src/policy.js";
import {
  differences,
  independence,
  independencePlan,
  reportFromMirror,
} from "../src/cli/independence.js";
import type { ValidatorIo } from "../src/cli/validator.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = "nmk_01J8ZQ2K7";
const AUTHOR_OPERATOR = "op_brightloop";
const SIGNATURE = example["signature"] as string;
const SNAPSHOT_HASH = example["snapshot_hash"] as string;
const HASH = `sha256:${"a".repeat(64)}`;
const INSIDE = ["op_v1", "op_v2"];
const OUTSIDE = "op_v3";
const NO_PERIMETER = "op_v4";
const VALIDATORS = [...INSIDE, OUTSIDE, NO_PERIMETER];
const PERIMETER = "nomankind";

class Log {
  readonly events: Event[] = [];
  private next = 0;

  add<T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
  ): void {
    this.push(type, entryId, payload);
  }

  /**
   * One event of a type this build does not know, which is the whole point of
   * the seam: builder C adds `public_confirmation` to src/events.ts later, and
   * the fold has to read it correctly without it.
   */
  addUnknown(type: string, entryId: string | null, payload: unknown): void {
    this.push(type as EventType, entryId, payload as Event["payload"]);
  }

  private push(
    type: EventType,
    entryId: string | null,
    payload: Event["payload"],
  ): void {
    const seq = this.next;
    this.next += 1;
    this.events.push({
      seq,
      at: new Date(
        Date.parse("2026-09-01T00:00:00Z") + seq * 60_000,
      ).toISOString(),
      type,
      entry_id: entryId,
      payload,
      prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
      hash: `hash-${seq}`,
    });
  }
}

function coreFrom(overrides: Record<string, unknown>): Core {
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) core[key] = example[key];
  core["author_operator"] = AUTHOR_OPERATOR;
  return { ...core, ...overrides } as Core;
}

function approval(
  operator: string,
  signedAt: string,
  extra: Record<string, unknown> = {},
): ApproverRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: HASH,
    assigned_random: false,
    test_accepted: true,
    reproduction: null,
    observation: {
      method: "endpoint_error",
      receipt_hash: HASH,
      observed_at: "2026-09-01",
      runs: 10,
      holds: 10,
    },
    signed_at: signedAt,
    ...extra,
  } as unknown as ApproverRecord;
}

/**
 * The registry every case below starts from: two operators inside one
 * disclosed perimeter, one inside another, one named with none at all.
 */
function baseLog(): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: "op_maintainer",
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  for (const operator of VALIDATORS) {
    log.add("operator_registered", null, { operator, maintainer: false });
    log.add("agent_bound", null, {
      operator,
      agent: `1F916:agent-${operator}`,
      attestation: {} as never,
    });
  }
  named(log, INSIDE[0]!, PERIMETER);
  named(log, INSIDE[1]!, PERIMETER);
  named(log, OUTSIDE, "elsewhere");
  named(log, NO_PERIMETER, null);
  return log;
}

/** One genesis naming, with the perimeter the maintainer disclosed or none. */
function named(log: Log, operator: string, perimeter: string | null): void {
  const payload: Record<string, unknown> =
    perimeter === null ? { operator } : { operator, perimeter };
  log.add("operator_trusted", null, payload as { operator: string });
}

function submit(log: Log, id: string): void {
  log.add("entry_submitted", id, { core: coreFrom({ id }), signature: SIGNATURE });
}

/** Two approvals from distinct operators: enough to verify in a small pool. */
function verifyBy(log: Log, id: string, first: string, second: string): void {
  log.add("validation", id, {
    record: approval(first, "2026-09-02T01:00:00Z"),
    signature: SIGNATURE,
  });
  log.add("validation", id, {
    record: approval(second, "2026-09-02T02:00:00Z"),
    signature: SIGNATURE,
  });
}

/** A verified entry decided by the two operators inside one perimeter. */
function bootstrapped(): Log {
  const log = baseLog();
  submit(log, ENTRY_ID);
  verifyBy(log, ENTRY_ID, INSIDE[0]!, INSIDE[1]!);
  return log;
}

function labelOf(log: Log): { perimeter: string } | null {
  const label = bootstrapLabelFor(log.events, ENTRY_ID);
  // The sidecar and the seam must never be two answers to one question.
  expect(
    deriveEntry(log.events, ENTRY_ID, { now: "2026-09-10T00:00:00Z" }).sidecar
      .bootstrap,
  ).toEqual(label);
  return label;
}

/**
 * One public confirmation, in the shape the door seals.
 *
 * `counted` is the door's own verdict on it (D-136): the confirmer's key had
 * sealed the line's fingerprint into the registry's log, with the proof on the
 * event. Only a counted one clears a label — an uncounted one is an account
 * statement, and the case below says so.
 */
function confirmation(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    entry_id: ENTRY_ID,
    venue: "1f916",
    handle: "morty-synctzn",
    verdict: "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    registry_event_id: "9134",
    counted: true,
    posted_at: "2026-09-05T00:00:00Z",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// The perimeter, folded out of the log
// ---------------------------------------------------------------------------

describe("operatorPerimetersAt", () => {
  it("folds the word the naming event disclosed, and nothing else", () => {
    const log = baseLog();
    const perimeters = operatorPerimetersAt(log.events, Number.MAX_SAFE_INTEGER);
    expect(perimeters.get(INSIDE[0]!)).toBe(PERIMETER);
    expect(perimeters.get(INSIDE[1]!)).toBe(PERIMETER);
    expect(perimeters.get(OUTSIDE)).toBe("elsewhere");
    // A naming with no perimeter carries no key, exactly as every naming
    // sealed before the decision does.
    expect(perimeters.has(NO_PERIMETER)).toBe(false);
    expect(perimeters.has("op_maintainer")).toBe(false);
  });

  it("is read at a position, like every other fold in derivation", () => {
    const log = baseLog();
    const namingSeq = log.events.find(
      (event) =>
        event.type === "operator_trusted" &&
        (event.payload as { operator: string }).operator === OUTSIDE,
    )!.seq;
    expect(
      operatorPerimetersAt(log.events, namingSeq - 1).has(OUTSIDE),
    ).toBe(false);
    expect(operatorPerimetersAt(log.events, namingSeq).get(OUTSIDE)).toBe(
      "elsewhere",
    );
  });

  it("ignores a payload whose perimeter is not a word", () => {
    const log = new Log();
    log.add("operator_registered", null, { operator: "op_x", maintainer: false });
    log.add("operator_trusted", null, { operator: "op_x", perimeter: 7 } as never);
    expect(
      operatorPerimetersAt(log.events, Number.MAX_SAFE_INTEGER).has("op_x"),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The bootstrap label
// ---------------------------------------------------------------------------

describe("the bootstrap label", () => {
  it("labels an entry every counted validator of which is inside one perimeter", () => {
    expect(labelOf(bootstrapped())).toEqual({ perimeter: PERIMETER });
  });

  it("labels nothing while the entry is still a draft", () => {
    const log = baseLog();
    submit(log, ENTRY_ID);
    log.add("validation", ENTRY_ID, {
      record: approval(INSIDE[0]!, "2026-09-02T01:00:00Z"),
      signature: SIGNATURE,
    });
    expect(labelOf(log)).toBeNull();
  });

  it("labels nothing when two counted validators sit in different perimeters", () => {
    const log = baseLog();
    submit(log, ENTRY_ID);
    verifyBy(log, ENTRY_ID, INSIDE[0]!, OUTSIDE);
    expect(labelOf(log)).toBeNull();
  });

  it("labels nothing when a counted validator is inside no perimeter at all", () => {
    const log = baseLog();
    submit(log, ENTRY_ID);
    verifyBy(log, ENTRY_ID, INSIDE[0]!, NO_PERIMETER);
    expect(labelOf(log)).toBeNull();
  });

  it("clears on a reconfirmation from outside the perimeter, and not from inside", () => {
    const inside = bootstrapped();
    inside.add("reconfirmation", ENTRY_ID, {
      record: {
        agent: `1F916:agent-${INSIDE[1]!}`,
        operator: INSIDE[1]!,
        snapshot_hash: SNAPSHOT_HASH,
        reproduction: null,
        observation: null,
        signed_at: "2026-09-06T00:00:00Z",
      },
      signature: SIGNATURE,
    } as never);
    expect(labelOf(inside)).toEqual({ perimeter: PERIMETER });

    const outside = bootstrapped();
    outside.add("reconfirmation", ENTRY_ID, {
      record: {
        agent: `1F916:agent-${OUTSIDE}`,
        operator: OUTSIDE,
        snapshot_hash: SNAPSHOT_HASH,
        reproduction: null,
        observation: null,
        signed_at: "2026-09-06T00:00:00Z",
      },
      signature: SIGNATURE,
    } as never);
    expect(labelOf(outside)).toBeNull();
  });

  it("clears on a revalidation resolved from outside the perimeter", () => {
    const log = bootstrapped();
    log.add("revalidation_requested", ENTRY_ID, {
      requester: null,
      operator: null,
      source: "failure_reports",
    });
    const requestSeq = log.events[log.events.length - 1]!.seq;
    log.add("revalidation_resolved", ENTRY_ID, {
      request_seq: requestSeq,
      outcome: "held",
      checker: `1F916:agent-${OUTSIDE}`,
      operator: OUTSIDE,
      snapshot_hash: SNAPSHOT_HASH,
      correction_entry_id: null,
    });
    expect(labelOf(log)).toBeNull();
  });

  it("resolves a revalidation's checker through the agent bindings", () => {
    // The operator field is null on an upgrade nobody checked; a resolution
    // that names only the checking agent still names an operator, through the
    // same bindings every other rule resolves an agent with.
    const log = bootstrapped();
    log.add("revalidation_requested", ENTRY_ID, {
      requester: null,
      operator: null,
      source: "failure_reports",
    });
    const requestSeq = log.events[log.events.length - 1]!.seq;
    log.add("revalidation_resolved", ENTRY_ID, {
      request_seq: requestSeq,
      outcome: "held",
      checker: `1F916:agent-${OUTSIDE}`,
      operator: null,
      snapshot_hash: SNAPSHOT_HASH,
      correction_entry_id: null,
    });
    expect(labelOf(log)).toBeNull();
  });

  it("is not cleared by another entry's reconfirmation", () => {
    const log = bootstrapped();
    submit(log, "nmk_other");
    log.add("reconfirmation", "nmk_other", {
      record: {
        agent: `1F916:agent-${OUTSIDE}`,
        operator: OUTSIDE,
        snapshot_hash: SNAPSHOT_HASH,
        reproduction: null,
        observation: null,
        signed_at: "2026-09-06T00:00:00Z",
      },
      signature: SIGNATURE,
    } as never);
    expect(labelOf(log)).toEqual({ perimeter: PERIMETER });
  });
});

// ---------------------------------------------------------------------------
// The seam: a public confirmation, from an event type this build does not know
// ---------------------------------------------------------------------------

describe("the public-confirmation seam", () => {
  it("names the type builder C's door will seal", () => {
    expect(PUBLIC_CONFIRMATION_EVENT).toBe("public_confirmation");
  });

  it("clears on an approve whose hash reproduces, from a handle outside", () => {
    const log = bootstrapped();
    log.addUnknown(PUBLIC_CONFIRMATION_EVENT, ENTRY_ID, confirmation());
    expect(labelOf(log)).toBeNull();
  });

  it("clears on an approve whose span the confirmer read present", () => {
    const log = bootstrapped();
    log.addUnknown(
      PUBLIC_CONFIRMATION_EVENT,
      ENTRY_ID,
      confirmation({ check: { kind: "span", value: "present" } }),
    );
    expect(labelOf(log)).toBeNull();
  });

  it("clears nothing when the check did not reproduce", () => {
    for (const check of [
      { kind: "hash", value: `sha256:${"b".repeat(64)}` },
      { kind: "span", value: "absent" },
      { kind: "quote", value: "present" },
      null,
      "hash",
    ]) {
      const log = bootstrapped();
      log.addUnknown(PUBLIC_CONFIRMATION_EVENT, ENTRY_ID, confirmation({ check }));
      expect(labelOf(log)).toEqual({ perimeter: PERIMETER });
    }
  });

  it("clears nothing on a reject, however well it reproduced", () => {
    const log = bootstrapped();
    log.addUnknown(
      PUBLIC_CONFIRMATION_EVENT,
      ENTRY_ID,
      confirmation({ verdict: "reject" }),
    );
    expect(labelOf(log)).toEqual({ perimeter: PERIMETER });
  });

  it("clears nothing when the handle is itself inside a disclosed perimeter", () => {
    // A confirmation from a key the maintainer already stands behind is not
    // the outside confirmation the label is waiting for -- by operator id, and
    // by an agent bound to one.
    for (const handle of [INSIDE[0]!, `1F916:agent-${INSIDE[1]!}`, OUTSIDE]) {
      const log = bootstrapped();
      log.addUnknown(PUBLIC_CONFIRMATION_EVENT, ENTRY_ID, confirmation({ handle }));
      expect(labelOf(log)).toEqual({ perimeter: PERIMETER });
    }
    // An operator inside no perimeter at all is outside every one of them.
    const log = bootstrapped();
    log.addUnknown(
      PUBLIC_CONFIRMATION_EVENT,
      ENTRY_ID,
      confirmation({ handle: NO_PERIMETER }),
    );
    expect(labelOf(log)).toBeNull();
  });

  it("clears nothing when the confirmation is about another entry", () => {
    const log = bootstrapped();
    log.addUnknown(
      PUBLIC_CONFIRMATION_EVENT,
      null,
      confirmation({ entry_id: "nmk_other" }),
    );
    expect(labelOf(log)).toEqual({ perimeter: PERIMETER });
  });

  it("clears nothing for a statement the door did not count", () => {
    // D-136: a comment is an account's word until its author seals the line's
    // fingerprint into the registry. The label answers keys, not accounts.
    const log = bootstrapped();
    log.addUnknown(
      PUBLIC_CONFIRMATION_EVENT,
      ENTRY_ID,
      confirmation({ counted: false }),
    );
    expect(labelOf(log)).toEqual({ perimeter: PERIMETER });
  });

  it("leaves every other field of the derivation untouched", () => {
    const log = bootstrapped();
    const before = deriveEntry(log.events, ENTRY_ID, {
      now: "2026-09-10T00:00:00Z",
    });
    log.addUnknown(PUBLIC_CONFIRMATION_EVENT, ENTRY_ID, confirmation());
    const after = deriveEntry(log.events, ENTRY_ID, {
      now: "2026-09-10T00:00:00Z",
    });
    expect(after.entry).toEqual(before.entry);
    expect(after.derived).toEqual(before.derived);
    // The label and the list of what was said are the two fields a
    // confirmation touches (D-136); every other field is the same derivation.
    expect({ ...after.sidecar, bootstrap: null, confirmations: [] }).toEqual({
      ...before.sidecar,
      bootstrap: null,
      confirmations: [],
    });
    expect(after.sidecar.confirmations).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The independence report
// ---------------------------------------------------------------------------

function validator(
  operator: string,
  perimeter: string | null,
  over: Partial<ValidatorEntry> = {},
): ValidatorEntry {
  return {
    operator,
    // A domain operator, which is what every validator in these cases is
    // (D-138): the community half has its own tests.
    kind: "domain",
    venue: null,
    handle: null,
    trusted: true,
    maintainer: false,
    provider: false,
    domains: ["ai-ecosystem"],
    perimeter,
    ...over,
  };
}

function report(validators: readonly ValidatorEntry[], counted: string[] = []) {
  return independenceReport({
    validators,
    pin: WITNESS_PIN,
    counted: counted.map((agent) => ({ agent, head: null })),
    boundOperators: new Map(),
    sealSeq: 4,
  });
}

describe("validator_perimeters", () => {
  it("groups the validator set by the word each naming disclosed", () => {
    const grouped = validatorPerimeters([
      validator("a.example", PERIMETER),
      validator("b.example", null),
      validator("c.example", PERIMETER),
      validator("d.example", "elsewhere"),
    ]);
    expect(grouped).toEqual({
      [PERIMETER]: ["a.example", "c.example"],
      elsewhere: ["d.example"],
    });
  });

  it("is empty, and not absent, when nothing is disclosed", () => {
    const answer = report([validator("a.example", null)]);
    expect(answer.validator_perimeters).toEqual({});
  });

  it("answers the one perimeter only when the whole set is inside it", () => {
    expect(
      singleValidatorPerimeter([
        validator("a.example", PERIMETER),
        validator("b.example", PERIMETER),
      ]),
    ).toBe(PERIMETER);
    expect(
      singleValidatorPerimeter([
        validator("a.example", PERIMETER),
        validator("b.example", "elsewhere"),
      ]),
    ).toBeNull();
    expect(
      singleValidatorPerimeter([
        validator("a.example", PERIMETER),
        validator("b.example", null),
      ]),
    ).toBeNull();
    expect(singleValidatorPerimeter([])).toBeNull();
  });
});

describe("the claim", () => {
  it("keeps the three it had, and puts the perimeter ahead of the external one", () => {
    expect(claimFor(0, false, null)).toBe(CLAIM_NONE_COUNTED);
    expect(claimFor(0, true, null)).toBe(CLAIM_EXTERNAL);
    expect(claimFor(1, true, null)).toBe(CLAIM_SHARED_PERIMETER);
    // A witness outside the validators says nothing about who judged the facts
    // underneath the seal, so a validator set that is one disclosed grouping
    // takes the words back.
    expect(claimFor(0, true, PERIMETER)).toBe(CLAIM_SINGLE_PERIMETER);
    expect(claimFor(0, false, PERIMETER)).toBe(CLAIM_SINGLE_PERIMETER);
    // The intersection is still the strongest fact there is about the two sets.
    expect(claimFor(1, true, PERIMETER)).toBe(CLAIM_SHARED_PERIMETER);
  });

  it("reads the perimeter claim off the report's own validator set", () => {
    const counted = [witnessAgentId(WITNESS_PIN[0]!.public_key)];
    const inside = report(
      [validator("a.example", PERIMETER), validator("b.example", PERIMETER)],
      counted,
    );
    expect(inside.claim).toBe(CLAIM_SINGLE_PERIMETER);
    // The flag itself is untouched by the distinction: it goes on answering
    // the question it was asked, about the witness set alone.
    expect(
      inside.external_witness_outside_validator_and_subject_provider_control,
    ).toBe(true);

    const mixed = report(
      [validator("a.example", PERIMETER), validator("b.example", null)],
      counted,
    );
    expect(mixed.claim).toBe(CLAIM_EXTERNAL);
  });
});

describe("derived_from", () => {
  it("names a row source and an address for every part of the page", () => {
    const answer = report([validator("a.example", null)]);
    expect(answer.derived_from).toBe(DERIVED_FROM);
    expect(Object.keys(answer.derived_from)).toEqual([
      "validator_set",
      "validator_perimeters",
      "witness_set",
      "counted_and_head",
      "intersection",
      "claim_and_flag",
    ]);
    for (const entry of Object.values(answer.derived_from)) {
      expect(entry.rows.length).toBeGreaterThan(0);
      expect(entry.published_at.length).toBeGreaterThan(0);
      expect(entry.note.length).toBeGreaterThan(0);
    }
    // The rows D-132 asks for by name.
    expect(answer.derived_from["witness_set"]!.rows).toContain("WITNESS_PIN");
    expect(answer.derived_from["intersection"]!.rows).toEqual([
      "agent_bound_to_operator",
      "handle_is_operator_id",
    ]);
    for (const row of [
      "witnesses",
      "leaf_index",
      "proof",
      "proved_at",
      "consistency_proof",
    ]) {
      expect(answer.derived_from["counted_and_head"]!.rows).toContain(row);
    }
  });

  it("is frozen, row and all: it is a map and never a variable", () => {
    expect(Object.isFrozen(DERIVED_FROM)).toBe(true);
    for (const entry of Object.values(DERIVED_FROM)) {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(Object.isFrozen(entry.rows)).toBe(true);
      expect(Object.isFrozen(entry.published_at)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// npm run independence
// ---------------------------------------------------------------------------

const directories: string[] = [];

async function mirrorDir(
  operators: Record<string, unknown>,
  seals: readonly Record<string, unknown>[],
): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "nmk-independence-"));
  directories.push(dir);
  await writeFile(join(dir, "operators.json"), JSON.stringify(operators));
  await writeFile(
    join(dir, "seals.jsonl"),
    seals.map((seal) => JSON.stringify(seal)).join("\n") + "\n",
  );
  return dir;
}

afterAll(async () => {
  for (const dir of directories) await rm(dir, { recursive: true, force: true });
});

/** A mirror with two operators in one perimeter and a seal nobody witnessed. */
function operatorsFile(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    operators: [
      {
        operator: "a.example",
        maintainer: false,
        provider: false,
        trusted: true,
        domains: ["ai-ecosystem"],
        agents: ["1F916:agent-a"],
        perimeter: PERIMETER,
      },
      {
        operator: "b.example",
        maintainer: false,
        provider: false,
        trusted: true,
        domains: ["ai-ecosystem"],
        agents: ["1F916:agent-b"],
        perimeter: PERIMETER,
      },
    ],
    agents: { "1F916:agent-a": "a.example", "1F916:agent-b": "b.example" },
    ...over,
  };
}

const SEALS = [
  { seq: 3, witnesses: [], registry: null },
  { seq: 4, witnesses: [], registry: null },
];

function capture(): { io: ValidatorIo; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (line) => out.push(line), stderr: (line) => err.push(line) },
    out,
    err,
  };
}

describe("npm run independence", () => {
  it("reads its one argument and its one flag, and refuses anything else", () => {
    expect(independencePlan(["../log/demo"])).toEqual({
      dir: "../log/demo",
      compare: null,
    });
    expect(independencePlan(["../log/demo", "--compare", "served.json"])).toEqual(
      { dir: "../log/demo", compare: "served.json" },
    );
    for (const args of [
      [],
      ["--compare", "served.json"],
      ["../log/demo", "--compare"],
      ["../log/demo", "--compare", "--entry"],
      ["../log/demo", "--entry", "x"],
      ["../log/demo", "--compare", "a", "--compare", "b"],
    ]) {
      expect(independencePlan(args)).toBeNull();
    }
  });

  it("recomputes the whole report from a mirror and the policy module", async () => {
    const dir = await mirrorDir(operatorsFile(), SEALS);
    const answer = await reportFromMirror(dir);

    expect(answer.validator_set.map((each) => each.operator)).toEqual([
      "a.example",
      "b.example",
    ]);
    expect(answer.validator_perimeters).toEqual({
      [PERIMETER]: ["a.example", "b.example"],
    });
    // The witness set is src/policy.ts's and nothing the mirror carries.
    expect(answer.witness_set.map((each) => each.id)).toEqual(
      WITNESS_PIN.map((pin) => pin.id),
    );
    // The newest seal, by seq, and nothing witnessed it: the demo's own case.
    expect(answer.seal_seq).toBe(4);
    expect(answer.witness_set.every((each) => !each.counted)).toBe(true);
    expect(
      answer.external_witness_outside_validator_and_subject_provider_control,
    ).toBe(false);
    expect(answer.intersection).toEqual([]);
    expect(answer.claim).toBe(CLAIM_SINGLE_PERIMETER);
  });

  it("reads a mirror written before the perimeter existed", async () => {
    const before = operatorsFile();
    for (const row of before["operators"] as Record<string, unknown>[]) {
      delete row["perimeter"];
    }
    const answer = await reportFromMirror(await mirrorDir(before, SEALS));
    expect(answer.validator_perimeters).toEqual({});
    expect(answer.claim).toBe(CLAIM_NONE_COUNTED);
  });

  it("prints the report and exits 0 with nothing to compare against", async () => {
    const dir = await mirrorDir(operatorsFile(), SEALS);
    const { io, out } = capture();
    expect(await independence([dir], io)).toBe(0);
    expect(JSON.parse(out.join("\n")).claim).toBe(CLAIM_SINGLE_PERIMETER);
  });

  it("reproduces a served page it agrees with, the seal position aside", async () => {
    const dir = await mirrorDir(operatorsFile(), SEALS);
    const served = { ...(await reportFromMirror(dir)), seal_seq: 9 };
    const path = join(dir, "served.json");
    await writeFile(path, JSON.stringify(served));

    const { io, out } = capture();
    expect(await independence([dir, "--compare", path], io)).toBe(0);
    // Named out loud rather than hidden: a mirror is a moment, the page is now.
    expect(out).toContain("position seal_seq mirror=4 served=9");
    expect(out.some((line) => line.startsWith("differs "))).toBe(false);
    expect(out.some((line) => line.startsWith("summary differences 0"))).toBe(
      true,
    );
  });

  it("prints one named difference per line when a set is altered by hand", async () => {
    const dir = await mirrorDir(operatorsFile(), SEALS);
    const served = await reportFromMirror(dir);
    const path = join(dir, "served.json");
    await writeFile(path, JSON.stringify(served));

    // The hand alteration: one operator untrusted, one perimeter renamed.
    const altered = operatorsFile();
    const rows = altered["operators"] as Record<string, unknown>[];
    rows[0]!["trusted"] = false;
    rows[1]!["perimeter"] = "elsewhere";
    const alteredDir = await mirrorDir(altered, SEALS);

    const { io, out } = capture();
    expect(await independence([alteredDir, "--compare", path], io)).toBe(1);
    expect(out).toContain(
      "differs validator_set[0].trusted mirror=false served=true",
    );
    expect(out).toContain(
      'differs validator_set[1].perimeter mirror="elsewhere" served="nomankind"',
    );
    expect(out).toContain(
      `differs claim mirror="${CLAIM_NONE_COUNTED}" served="${CLAIM_SINGLE_PERIMETER}"`,
    );
  });

  it("names a whole missing subtree once rather than forty times", () => {
    expect(differences({ a: { b: 1, c: 2 } }, {})).toEqual([
      { path: "a", mirror: '{"b":1,"c":2}', served: "(absent)" },
    ]);
    expect(differences([1, 2], [1])).toEqual([
      { path: "[1]", mirror: "2", served: "(absent)" },
    ]);
    expect(differences({ a: 1 }, { a: 1 })).toEqual([]);
  });

  it("answers usage on bad arguments and a named line on a directory it cannot read", async () => {
    const usage = capture();
    expect(await independence([], usage.io)).toBe(2);
    expect(usage.err[0]).toMatch(/^usage: independence /);

    const missing = capture();
    expect(await independence([join(tmpdir(), "nmk-nothing-here")], missing.io)).toBe(
      1,
    );
    expect(missing.err[0]).toMatch(/operators\.json: cannot read: ENOENT/);
  });
});
