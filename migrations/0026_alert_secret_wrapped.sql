-- 0026_alert_secret_wrapped: an alert endpoint's shared secret, wrapped at rest
-- (decision D-118 item a, M25a).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0025 are closed; this
-- file reshapes one table and adds one column, and never touches a row's
-- meaning.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- WHY. Migration 0015 created `alert_endpoints.secret` and said what it was in
-- its own comment: "the shared secret (base64url, 32 bytes); stored plain, a
-- GAP for at-rest encryption". That secret is the key a subscriber verifies
-- every delivery's HMAC with, so a copy of this database is a copy of every
-- subscriber's signing key, and anybody holding one can forge an alert that
-- verifies. D-118 item a is the decision to close it, and this is the column it
-- closes with.
--
-- WHAT IS STORED. `secret_wrapped` holds the AES-GCM ciphertext of the same
-- base64url secret under a key derived from the ALERT_SIGNING_KEY Worker secret
-- with HKDF-SHA-256 -- the salt a constant in src/alerts.ts, the info the
-- endpoint's own id, so one endpoint's ciphertext is under a key no other
-- endpoint shares. The IV travels with the ciphertext in the same string
-- (src/alerts.ts, `wrapAlertSecret`), because an IV is not a secret and a
-- second column for it would be a second thing to keep in step.
--
-- The key itself is in no column and in no migration: it is a Worker secret, it
-- is never logged, and a database without it is a database of ciphertext. That
-- is the whole point of the column.
--
-- NOTHING HERE IS A SOURCE OF TRUTH ABOUT THE RECORD. An alert is a
-- notification of something already in the sealed log (src/alerts.ts); an
-- endpoint's secret decides who can check a delivery's signature and decides
-- nothing about any entry, any operator or any seal. No derivation reads this
-- table.
--
-- WHY THE TABLE IS REBUILT. `secret` was declared NOT NULL, and the whole
-- behaviour is that the plain column is nulled the moment the wrapped one is
-- written: a row whose secret is wrapped must hold no plain copy of it, and
-- leaving an empty string behind would be a plain column that merely looks
-- empty. SQLite cannot drop a NOT NULL, so the table is rebuilt -- the second
-- rebuild in this repository, after 0023's, and ordered by the same rule.
--
-- IF IT STOPS HALF WAY. `wrangler d1 migrations apply --remote` does not
-- promise that one file's statements land as one transaction, so nothing before
-- the two renames is destructive:
--
--   * stopped after CREATE or after the INSERT: `alert_endpoints` is untouched
--     and readable, and the copy stands beside it under a name nothing reads.
--     Recover by hand with `DROP TABLE alert_endpoints_wrapped;` and re-run.
--   * stopped between the two renames -- the one statement after which
--     `alert_endpoints` does not exist: every row is still there, under
--     `alert_endpoints_wrapped`. Recover with
--     `ALTER TABLE alert_endpoints_wrapped RENAME TO alert_endpoints;` and
--     apply the rest by hand; or rename `alert_endpoints_plain` back and
--     re-run the file from the top.
--   * stopped after the second rename: `alert_endpoints` is readable and
--     already the new shape. Apply the statements after the stop by hand; a
--     re-run would fail on a table it has already dropped.
--
-- The `d1_migrations` row is written only when every statement has landed, so a
-- stop always leaves the file unrecorded and a re-run always starts at the top:
-- that is why the recovery above is a hand step and not another migration.

-- The endpoints table, rebuilt with a nullable plain secret and the wrapped one
-- beside it. Every other column, and every value in it, is 0015's unchanged.
--
-- Exactly one of the two is set on a row that is in either state this build can
-- produce: `secret` alone on a deployment with no ALERT_SIGNING_KEY, and
-- `secret_wrapped` alone once the key is set and the row has been wrapped. A
-- row with neither is an endpoint nothing can sign for, which delivery refuses
-- rather than sends unsigned; a row with both is what nothing writes.
CREATE TABLE alert_endpoints_wrapped (
  id             TEXT PRIMARY KEY,   -- "hook_" + 16 hex
  key_id         TEXT NOT NULL,
  url            TEXT NOT NULL,
  secret         TEXT,               -- the plain shared secret, or NULL once wrapped
  secret_wrapped TEXT,               -- "<iv>.<ciphertext>", both unpadded base64url
  domain         TEXT,               -- filters, null = any
  subject        TEXT,
  category       TEXT,
  kinds_json     TEXT,               -- JSON array of AlertKind, null = every kind
  created_at     TEXT NOT NULL,
  disabled_at    TEXT
);

-- Every row as it stands, with nothing wrapped yet: wrapping is the sweep's
-- work and needs the Worker secret, which no migration has. A deployment that
-- never sets the key stays exactly here, which is the behaviour this file
-- promises not to change.
INSERT INTO alert_endpoints_wrapped
  (id, key_id, url, secret, secret_wrapped, domain, subject, category,
   kinds_json, created_at, disabled_at)
SELECT id, key_id, url, secret, NULL, domain, subject, category,
       kinds_json, created_at, disabled_at
FROM alert_endpoints;

ALTER TABLE alert_endpoints RENAME TO alert_endpoints_plain;
ALTER TABLE alert_endpoints_wrapped RENAME TO alert_endpoints;
DROP TABLE alert_endpoints_plain;

-- "Which endpoints belong to this key?": what the webhook doors and the cap
-- ask. 0015's index, recreated on the rebuilt table -- a DROP TABLE takes its
-- indexes with it.
CREATE INDEX alert_endpoints_key ON alert_endpoints (key_id);

-- "Which live endpoints are still holding a plain secret?": the bounded pass in
-- the alerts step that wraps the legacy rows, a few per run. A partial index,
-- because the rows it answers about are the ones this migration exists to make
-- disappear: it is empty on a deployment that has finished wrapping, which is
-- where every deployment that sets the key ends up, and a row leaves it by
-- being wrapped or by being turned off rather than by being deleted.
CREATE INDEX alert_endpoints_plain_secret
  ON alert_endpoints (id)
  WHERE secret IS NOT NULL AND disabled_at IS NULL;
