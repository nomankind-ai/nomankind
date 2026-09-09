/**
 * What each page is handed.
 *
 * The browsing UI is server-rendered from the Worker and every page is a pure
 * function of one of these shapes: the route reads storage, the page renders,
 * and nothing in src/ui/ touches a database, a clock or the network. That is
 * what makes a page testable without a Worker and what keeps derivation out of
 * the view — every field below was computed by src/derive.ts or src/seal.ts and
 * is carried here verbatim.
 *
 * Whitepaper Section 3, The log: "every field a reader needs to check an entry
 * offline is visible on the entry". So the entry page is handed the entry
 * itself, its sidecar, its events and its seal rather than a summary of them,
 * and the field names below are the schema's own — never an alias.
 */

import type { Sidecar } from "../derive.js";
import type { Event } from "../events.js";
import type { Seal } from "../seal.js";

/**
 * The three things every page knows about the request it is answering, and
 * nothing else. No bindings, no database, no clock: a page that could reach any
 * of those would stop being a function of its data.
 *
 * `environment` is the `ENVIRONMENT` var (local, demo, production) shown in the
 * header badge; `path` is the request's pathname, which decides which nav item
 * is active; `origin` is the scheme and host the page was reached at, for the
 * absolute URLs an example command has to spell out.
 */
export interface PageContext {
  readonly environment: string;
  readonly path: string;
  readonly origin: string;
}

/**
 * One row of a dense entry table. Every value is already derived and already
 * formatted-agnostic: the row carries the field, the page decides how it looks.
 */
export interface EntryRow {
  id: string;
  /** The entry's sealed position in the log: its `entry_submitted` seq. */
  position: number;
  /** Whether a seal covers that position yet. */
  sealed: boolean;
  status: string;
  subject: string;
  category: string;
  claim: string;
  /** The sidecar's `effective_tier`, null while the entry is draft or rejected. */
  tier: string | null;
  last_confirmed: string;
  expires_at: string | null;
  stale: boolean;
}

/** The counters across the top of the home page. */
export interface HomeCounters {
  verified: number;
  stale: number;
  /** Operators in the trusted pool (Section 5). */
  trusted: number;
  /** The newest seal's last covered event seq, null before anything is sealed. */
  sealedHead: number | null;
  sealedAt: string | null;
  /** Countersignatures on that seal, null when there is no seal. */
  witnesses: number | null;
  seals: number;
}

export interface HomeData {
  counters: HomeCounters;
  latest: EntryRow[];
}

/** What an entries listing was narrowed by; null in a field means "not asked". */
export interface EntriesFilter {
  category: string | null;
  status: string | null;
  tier: string | null;
  fresh: "fresh" | "stale" | null;
}

export interface EntriesData {
  filter: EntriesFilter;
  rows: EntryRow[];
  /** How many entries match the filter, ignoring the page. */
  total: number;
  /** The keyset cursor for the next page: `?before=<position>`, null at the end. */
  nextBefore: number | null;
}

/**
 * One decision on an entry, exactly as the schema's approvers[] item carries it,
 * plus the two things the log knows and the record does not: whether the
 * deciding operator is trusted, and where the decision sits in the log.
 */
export interface ApproverRow {
  agent: string;
  operator: string;
  operatorTrusted: boolean | null;
  decision: string;
  reason: string | null;
  snapshot_hash: string | null;
  assigned_random: boolean;
  test_accepted: boolean | null;
  reproduction: unknown;
  observation: unknown;
  signed_at: string;
  /** seq of the `validation` event, null when it is not known. */
  seq: number | null;
}

export interface EntryData {
  /** The entry exactly as derivation left it; the schema's field names. */
  entry: Record<string, unknown>;
  sidecar: Sidecar;
  /** The entry's sealed position: its `entry_submitted` seq. */
  position: number;
  events: Event[];
  /** The seal covering the entry's submission, null until one does. */
  seal: Seal | null;
  approvers: ApproverRow[];
  reconfirmations: Array<{
    record: Record<string, unknown>;
    seq: number | null;
    operatorTrusted: boolean | null;
  }>;
  /** Entry ids declaring they supersede this one. */
  superseders: string[];
  /** The window from policy for this entry's category, null for an event category. */
  stalenessWindowDays: number | null;
}

export interface OperatorRow {
  id: string;
  maintainer: boolean;
  provider: boolean;
  trusted: boolean;
  /** seq of the `operator_trusted` event, null when never trusted. */
  trustedSeq: number | null;
  registeredSeq: number;
  agents: number;
  validations: number;
}

export interface OperatorsData {
  rows: OperatorRow[];
}

export interface OperatorData {
  row: OperatorRow;
  /** The agent ids bound to the operator (Section 5). */
  agents: string[];
  /** The signed independence attestation, null when the row carries none. */
  attestation: Record<string, unknown> | null;
  /** The agent that named this operator at genesis, null otherwise. */
  namedBy: string | null;
  payoutStatus: string | null;
  validations: Array<{
    entryId: string;
    decision: string;
    seq: number;
    signed_at: string;
  }>;
}

/** One candidate or member of the founding trusted pool (Section 11, genesis). */
export interface GenesisRow {
  operator: string;
  registeredSeq: number;
  trustedSeq: number | null;
  validations: number;
  lastValidationAt: string | null;
}

export interface GenesisData {
  rows: GenesisRow[];
  /** The attestation text an operator signs to register, verbatim. */
  attestationText: string;
  attestationVersion: string;
  /** The prefix of the DNS TXT record that proves domain control. */
  txtRecordPrefix: string;
  /** Whether this environment has a maintainer configured at all (D-016). */
  maintainerConfigured: boolean;
}
