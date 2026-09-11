-- 0015_paid_access: keys, quota, the per-key receipt columns, the provider's
-- events, what was metered, and the change-alert tables (M24, whitepaper
-- Section 9 "Money": "The log is free to read at low volume, forever. Revenue
-- comes from high-rate API access, structured feeds and webhooks, change
-- alerts").
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0014 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth about the log. A key is an access
-- credential and a quota row is a counter; the record of what was read is the
-- receipts table and the sealed `read_count` events, exactly as it was before
-- this file existed. Drop every table here and the log is untouched.

-- One row per API key. The secret itself is never stored: `key_hash` is the
-- SHA-256 hex of the secret the reader was shown once, which is what the access
-- gate looks a bearer token up by, so a copy of this table cannot be used to
-- read as anybody.
--
-- `subscription` and `checkout_session` are UNIQUE because each is a claim on a
-- thing that can be claimed once: one subscription pays for one key, and a
-- checkout session mints one key however many times its success URL is opened.
-- The 409 the claim door answers is this index, not a check the door made and
-- hoped nobody raced.
--
-- `counter` is the key's own receipt counter, the last number it was issued.
-- Separate from the log-wide running counter in `receipts.seq` because a reader
-- must be able to say "I hold reads 1 through n of mine" without knowing what
-- anybody else read.
CREATE TABLE api_keys (
  id               TEXT PRIMARY KEY,           -- "key_" + 16 lowercase hex
  key_hash         TEXT NOT NULL UNIQUE,       -- sha256 hex of the secret
  tier             TEXT NOT NULL,
  status           TEXT NOT NULL,              -- active | past_due | canceled
  customer         TEXT NOT NULL,              -- provider customer id (cus_...)
  subscription     TEXT NOT NULL UNIQUE,       -- provider subscription id (sub_...)
  checkout_session TEXT NOT NULL UNIQUE,       -- the session the key was claimed from
  counter          INTEGER NOT NULL DEFAULT 0, -- the key's own receipt counter (last issued)
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

-- The day's reads, per scope. A paid scope is the key; a free scope is the
-- client, hashed, because a rate counter that stored addresses would be a log of
-- who read what and this system publishes counts, never readers.
--
-- One row per scope per UTC day, so the gate is a primary-key lookup and the
-- charge is one UPSERT. Nothing here is history: a row is a counter, and the
-- record of the reads themselves is the receipts table.
CREATE TABLE quota (
  scope TEXT NOT NULL,        -- "key:<id>" or "client:<sha256 hex of cf-connecting-ip>" or "client:anonymous"
  day   TEXT NOT NULL,        -- YYYY-MM-DD UTC
  reads INTEGER NOT NULL,
  PRIMARY KEY (scope, day)
);

-- Which key a receipt was issued to, and that key's own counter. Both null for
-- a free read, which is what every receipt issued before this migration is: the
-- columns are added rather than backfilled, because a free read is exactly what
-- those receipts were.
ALTER TABLE receipts ADD COLUMN key_id TEXT;
ALTER TABLE receipts ADD COLUMN key_counter INTEGER;

-- The per-key counter runs the same way the log-wide one does, so it needs the
-- same guard: two isolates serving one key at the same instant must not be
-- handed the same number. Partial, because every free read leaves both columns
-- null and a plain unique index would let exactly one of them exist.
CREATE UNIQUE INDEX receipts_key_counter ON receipts (key_id, key_counter) WHERE key_id IS NOT NULL;

-- Every provider event the webhook door has already applied. The primary key is
-- the guard: a provider retries, and a retried `customer.subscription.deleted`
-- must not cancel a key that was paid for again in between.
CREATE TABLE stripe_events (
  id          TEXT PRIMARY KEY,   -- evt_...
  type        TEXT NOT NULL,
  received_at TEXT NOT NULL,
  outcome     TEXT NOT NULL       -- applied | ignored | unknown_subscription
);

-- What was reported to the provider's meter, one row per key per day. The row is
-- written only after the provider accepted the number, and the primary key is
-- what stops a second sweep reporting the same day twice — `identifier` is the
-- idempotency string that was sent, so the two ends can be compared by hand.
CREATE TABLE meter_reports (
  key_id      TEXT NOT NULL,
  date        TEXT NOT NULL,
  event_seq   INTEGER NOT NULL,   -- the read_count event the number came from
  reads       INTEGER NOT NULL,
  identifier  TEXT NOT NULL,      -- the idempotency identifier sent
  reported_at TEXT NOT NULL,
  PRIMARY KEY (key_id, date)
);

-- A subscriber's webhook endpoint. The shared secret is stored plain, which is
-- named here as a GAP rather than left to be discovered: a delivery has to sign
-- with it, so it cannot be hashed, and encrypting it at rest needs a key
-- management story this deployment does not have yet.
--
-- An endpoint is disabled rather than deleted (`disabled_at`), so the deliveries
-- that name it keep naming something.
CREATE TABLE alert_endpoints (
  id          TEXT PRIMARY KEY,   -- "hook_" + 16 hex
  key_id      TEXT NOT NULL,
  url         TEXT NOT NULL,
  secret      TEXT NOT NULL,      -- the shared secret (base64url, 32 bytes); stored plain, a GAP for at-rest encryption
  domain      TEXT,               -- filters, null = any
  subject     TEXT,
  category    TEXT,
  kinds_json  TEXT,               -- JSON array of AlertKind, null = every kind
  created_at  TEXT NOT NULL,
  disabled_at TEXT
);

-- "Which endpoints belong to this key?": what the webhook doors and the cap ask.
CREATE INDEX alert_endpoints_key ON alert_endpoints (key_id);

-- One attempt to tell one endpoint about one sealed change. `body_json` is the
-- bytes that were signed and sent, verbatim, so a subscriber disputing a
-- signature can be shown exactly what it covered.
CREATE TABLE alert_deliveries (
  id           TEXT PRIMARY KEY,  -- "alert_" + 16 hex
  endpoint_id  TEXT NOT NULL,
  event_seq    INTEGER NOT NULL,
  kind         TEXT NOT NULL,
  entry_id     TEXT NOT NULL,
  body_json    TEXT NOT NULL,
  status       TEXT NOT NULL,     -- pending | delivered | failed
  attempts     INTEGER NOT NULL DEFAULT 0,
  next_at      TEXT NOT NULL,
  delivered_at TEXT,
  last_status  INTEGER,           -- last HTTP status, null when the fetch failed
  last_error   TEXT,
  created_at   TEXT NOT NULL
);

-- "What is due now?": the delivery step's only question, a bounded range on the
-- (status, next_at) pair rather than a scan of every delivery ever attempted.
CREATE INDEX alert_deliveries_due ON alert_deliveries (status, next_at);

-- "What happened to my endpoint?": one endpoint's deliveries, newest first.
CREATE INDEX alert_deliveries_endpoint ON alert_deliveries (endpoint_id, created_at);

-- The two new cursors over the sealed log, beside the ledger's own. Both start
-- at -1, which is "before the first event": seq 0 is a real position, so a
-- cursor of 0 would mean the first event had already been examined.
INSERT INTO ledger_state (name, seq) VALUES ('alerts', -1);   -- the alert step's cursor over sealed events (seq of the last sealed event examined)
INSERT INTO ledger_state (name, seq) VALUES ('metering', -1); -- the metering step's cursor over sealed read_count events
