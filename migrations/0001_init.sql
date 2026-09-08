-- 0001_init: the first and, so far, only schema for the D1 database.
--
-- Whitepaper Section 11, Deployment and status: the log is the product, so the
-- database is shaped around reading slices of it, never around loading it.
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. A correction is a new numbered file.
--
-- Every index here exists because a repository query needs it (src/storage/
-- repository.ts). Nothing in that module scans a whole table: every read is
-- either a primary-key lookup, a bounded range, or a keyset page ordered by a
-- monotonic log coordinate.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.

-- The append-only event log. Section 6, "Seal": the log is the record and
-- nothing is ever updated in place, so this table takes inserts only.
-- `payload` holds the event's payload as JSON exactly as the kernel produced
-- it, so an event read back is byte-identical to the one appended.
CREATE TABLE events (
  seq        INTEGER PRIMARY KEY,
  "at"       TEXT    NOT NULL,
  type       TEXT    NOT NULL,
  entry_id   TEXT,
  payload    TEXT    NOT NULL,
  prev_hash  TEXT,
  hash       TEXT    NOT NULL UNIQUE
);

-- An entry's lifecycle is the sub-sequence of the log bearing its id, so
-- reading one entry's history must be an index seek, not a scan.
CREATE INDEX events_entry_seq ON events (entry_id, seq);

-- The delta stream and the sealer both walk one event type forward from a
-- known position.
CREATE INDEX events_type_seq ON events (type, seq);

-- Derived entries. Status and every field beside it are recomputed from the
-- events by src/derive.ts and only stored here; nothing writes them directly,
-- and dropping this table loses nothing that cannot be rebuilt from `events`.
-- `entry_json` holds the entry exactly as deriveEntry produced it, `sidecar_json`
-- the sidecar the schema cannot carry, and `derived_through_seq` the log
-- position that derivation saw, so a stale row is recognisable as stale.
CREATE TABLE entries (
  id                  TEXT    PRIMARY KEY,
  subject             TEXT    NOT NULL,
  category            TEXT    NOT NULL,
  status              TEXT    NOT NULL,
  submitted_at        TEXT    NOT NULL,
  submitted_seq       INTEGER NOT NULL,
  author              TEXT    NOT NULL,
  entry_json          TEXT    NOT NULL,
  sidecar_json        TEXT    NOT NULL,
  derived_through_seq INTEGER NOT NULL
);

-- The subject page: everything known about one subject, one category at a time.
CREATE INDEX entries_subject_category_seq ON entries (subject, category, submitted_seq);

-- The status feeds: what is verified, what is still draft, newest last.
CREATE INDEX entries_status_seq ON entries (status, submitted_seq);

-- The unfiltered keyset page, and the ordering every other listing shares.
CREATE INDEX entries_submitted_seq ON entries (submitted_seq);

-- The registry. Section 5, Identity and operators: the operator is the unit of
-- accountability, and an agent is a key that answers for one.
-- `operator_json` carries whatever the columns do not, so the record round-trips
-- unchanged even as later milestones add fields to it.
CREATE TABLE operators (
  id             TEXT    PRIMARY KEY,
  maintainer     INTEGER NOT NULL,
  provider       INTEGER NOT NULL,
  registered_seq INTEGER NOT NULL,
  operator_json  TEXT    NOT NULL
);

CREATE TABLE agents (
  agent_id       TEXT    PRIMARY KEY,
  operator_id    TEXT    NOT NULL REFERENCES operators (id),
  registered_seq INTEGER NOT NULL
);

-- Assignments. An entry's open assignment is the newest row for it with no
-- missed_seq; `missed_seq` names the event that closed it, so the miss is a
-- position in the log rather than a flag someone set.
CREATE TABLE assignments (
  entry_id        TEXT    NOT NULL,
  seq             INTEGER PRIMARY KEY,
  operator_id     TEXT    NOT NULL,
  deadline        TEXT    NOT NULL,
  missed_seq      INTEGER,
  assignment_json TEXT    NOT NULL
);

CREATE INDEX assignments_entry_seq ON assignments (entry_id, seq);

-- Seals: contiguous runs of event seqs, committed and chained (src/seal.ts).
CREATE TABLE seals (
  seq            INTEGER PRIMARY KEY,
  first_seq      INTEGER NOT NULL,
  last_seq       INTEGER NOT NULL,
  size           INTEGER NOT NULL,
  root           TEXT    NOT NULL,
  sealed_at      TEXT    NOT NULL,
  prev_hash      TEXT,
  hash           TEXT    NOT NULL UNIQUE,
  witnesses_json TEXT    NOT NULL
);

-- "Which seal covers event N": seals are disjoint and ordered, so the covering
-- seal is the first one whose last_seq reaches N.
CREATE INDEX seals_last_seq ON seals (last_seq);

-- One anchor per UTC day (src/anchor.ts). `external` is the external timestamp
-- receipt, null until a later milestone posts the day's hash.
CREATE TABLE anchors (
  "date"          TEXT    PRIMARY KEY,
  first_seal_seq  INTEGER,
  last_seal_seq   INTEGER,
  roots_json      TEXT    NOT NULL,
  hash            TEXT    NOT NULL UNIQUE,
  external        TEXT
);

-- PLACEHOLDER TABLES.
--
-- `receipts` and `ledger` are declared now so the storage shape is settled and
-- no later migration has to reshape a live table under load. Nothing writes to
-- them yet: M17 fills `receipts` (the read receipts the metering story counts)
-- and M21 fills `ledger` (the read-share accounting, Incentives / Money). Both
-- keep the same query shape as the tables above: a primary key, a kind, the
-- subject the row is about, the log position it was produced at, and the
-- payload as JSON.
CREATE TABLE receipts (
  id           TEXT    PRIMARY KEY,
  kind         TEXT    NOT NULL,
  entry_id     TEXT,
  seq          INTEGER NOT NULL,
  created_at   TEXT    NOT NULL,
  payload_json TEXT    NOT NULL
);

CREATE TABLE ledger (
  id           TEXT    PRIMARY KEY,
  kind         TEXT    NOT NULL,
  operator_id  TEXT,
  seq          INTEGER NOT NULL,
  created_at   TEXT    NOT NULL,
  payload_json TEXT    NOT NULL
);
