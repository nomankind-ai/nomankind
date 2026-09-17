/**
 * Attribution: who an entry is owed to, in one block a reader can paste.
 *
 * Whitepaper Incentives as decision D-127 amends it: the record is free and
 * contribution is the currency, so what a contributor is paid in is
 * "attribution on every read, cite the validator" — and decision D-130 makes
 * that an asset rather than a courtesy: standing is public and named, and the
 * names beside a fact are the public half of it. This module is that block: the
 * author, every validator that decided the entry and which of them were drawn,
 * every reconfirmer that has checked it since, and one line of citation.
 *
 * Both kinds of operator on the one surface (D-138): a `validation` from a
 * domain operator and a `community_validation` from a community one are the
 * same fact here, and `kind` is what says which — so a reader citing an entry
 * cites everybody who decided it, in the order the log recorded them.
 *
 * Derived and never stored. The published entry object is closed to new keys
 * (`additionalProperties: false`), which is the reason this is a function over
 * the entry's own events rather than a field on it: the block is recomputed
 * wherever it is served, and a reader with the entry's events can recompute it
 * too and get the same lines.
 *
 * Cheap on purpose. The inputs are one entry's own events and the operator
 * kinds at the position — no registry walk, no derivation, no clock and no
 * I/O — so a door can answer it beside the entry it already read.
 */

import type { OperatorKind } from "./policy.js";
import type { ApproverRecord, Event } from "./events.js";
import type { Entry } from "./schema.js";

/** One validator's line: who decided, under what kind, and how it got there. */
export interface AttributionValidator {
  readonly agent: string;
  readonly operator: string;
  readonly kind: OperatorKind;
  readonly decision: "approve" | "reject";
  /** True when the draw picked this validator rather than it volunteering. */
  readonly assigned_random: boolean;
}

/** One reconfirmer's line: who checked it again, and when. */
export interface AttributionReconfirmer {
  readonly agent: string;
  readonly operator: string;
  readonly kind: OperatorKind;
  readonly at: string;
}

/**
 * Everyone one entry is owed to, and the line that names them.
 *
 * `author.operator` is null for a bare key, which Section 5 allows: anyone may
 * hold a key and submit with it, and null is the truth about one rather than an
 * absence to paper over.
 */
export interface Attribution {
  readonly author: { readonly agent: string; readonly operator: string | null };
  readonly validators: readonly AttributionValidator[];
  readonly reconfirmers: readonly AttributionReconfirmer[];
  /** One line a reader can paste, ending at the entry's sealed position. */
  readonly citation: string;
}

/** A string field off the entry, or null when it carries none. */
function text(entry: Entry, name: string): string | null {
  const value = entry[name];
  return typeof value === "string" ? value : null;
}

/** The sealed position the entry's own seal object names, or null. */
function sealPosition(entry: Entry): number | null {
  const seal = entry["seal"];
  if (typeof seal !== "object" || seal === null) return null;
  const position = (seal as Record<string, unknown>)["position"];
  return typeof position === "number" ? position : null;
}

/** Which kind an operator is at this position; a stranger reads as `domain`. */
function kindOf(
  kinds: ReadonlyMap<string, OperatorKind>,
  operator: string,
): OperatorKind {
  return kinds.get(operator) ?? "domain";
}

/**
 * The citation line.
 *
 * What a reader pastes under a fact they took from the record: the subject and
 * the category it was filed in, who verified it, the entry's own id and the
 * sealed position — everything somebody else needs to find the same entry and
 * check it for themselves, and nothing that would go stale between reads.
 *
 * An entry that has not verified says so instead of counting validators: a
 * draft is a claim nobody has confirmed, and a citation that read "verified by
 * 1 validator" of a draft would be the record overstating itself. The status
 * word is the entry's own (`draft`, `rejected`, `overturned`, `superseded`).
 */
function citationLine(
  entry: Entry,
  approvals: readonly AttributionValidator[],
): string {
  const subject = text(entry, "subject") ?? "(no subject)";
  const category = text(entry, "category") ?? "(no category)";
  const id = text(entry, "id") ?? "(no id)";
  const status = text(entry, "status") ?? "draft";
  const position = sealPosition(entry);
  const tail = `nomankind entry ${id}${
    position === null ? "" : `, seal position ${position}`
  }`;

  if (status !== "verified") {
    return `${subject} ${category}, ${status}, ${tail}`;
  }

  const operators = [...new Set(approvals.map((row) => row.operator))];
  const count = operators.length;
  return `${subject} ${category}, verified by ${count} validator${
    count === 1 ? "" : "s"
  } (${operators.join(", ")}), ${tail}`;
}

/**
 * Who one entry is owed to, folded out of its own events.
 *
 * `events` is the entry's own sub-sequence of the log, in any order — the fold
 * sorts by seq, because the order the block reads in is the order the log
 * recorded the work in and never the order a caller happened to page it.
 * Events about another entry are ignored rather than refused: a caller handing
 * in the whole log gets the same answer as one handing in the entry's events,
 * which is what makes this safe to call from a bundle.
 *
 * `operatorKinds` is `operatorKindsAt` (src/derive.ts) at the position being
 * served. An operator the map does not know reads as a domain operator, which
 * is what every operator was before D-138 and what a registration sealed before
 * it still means.
 */
export function attributionOf(
  entry: Entry,
  events: readonly Event[],
  operatorKinds: ReadonlyMap<string, OperatorKind>,
): Attribution {
  const entryId = text(entry, "id");
  const ordered = [...events]
    .filter((event) => entryId === null || event.entry_id === entryId)
    .sort((left, right) => left.seq - right.seq);

  const validators: AttributionValidator[] = [];
  const reconfirmers: AttributionReconfirmer[] = [];

  for (const event of ordered) {
    if (event.type === "validation") {
      const record = (event.payload as { record: ApproverRecord }).record;
      validators.push({
        agent: record.agent,
        operator: record.operator,
        kind: kindOf(operatorKinds, record.operator),
        decision: record.decision,
        assigned_random: record.assigned_random === true,
      });
      continue;
    }
    if (event.type === "community_validation") {
      // Read by name off the payload, exactly as the standing fold reads it: an
      // event shaped by a build this one does not know is skipped rather than
      // half-read into somebody's name.
      const payload = event.payload as unknown as Record<string, unknown>;
      const operator = payload["operator"];
      const agent = payload["agent"];
      const decision = payload["decision"];
      if (typeof operator !== "string" || typeof agent !== "string") continue;
      if (decision !== "approve" && decision !== "reject") continue;
      validators.push({
        agent,
        operator,
        // The event itself says which kind this is, so the map is not asked:
        // a `community_validation` is a community operator's by construction,
        // and a bundle that carries the entry's events without the registry's
        // still labels it right.
        kind: "community",
        decision,
        // Nobody draws a community validation: it is said in public, by
        // whoever chose to say it.
        assigned_random: false,
      });
      continue;
    }
    if (event.type === "reconfirmation") {
      const record = (
        event.payload as { record: { agent: string; operator: string } }
      ).record;
      reconfirmers.push({
        agent: record.agent,
        operator: record.operator,
        kind: kindOf(operatorKinds, record.operator),
        at: event.at,
      });
    }
  }

  const author = {
    agent: text(entry, "author") ?? "",
    operator: text(entry, "author_operator"),
  };

  return {
    author,
    validators: Object.freeze(validators),
    reconfirmers: Object.freeze(reconfirmers),
    citation: citationLine(
      entry,
      validators.filter((row) => row.decision === "approve"),
    ),
  };
}
