-- 0002_registry: the spent-nonce store the write path needs.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 is closed; this file adds and
-- never reshapes.
--
-- Decision D-014, request authentication: a signed write request carries a
-- single-use nonce, and a verifier that forgets one accepts the replay. The
-- in-process store (src/request.ts) cannot serve that, because a Worker isolate
-- that handles two requests may not be the isolate that handles the third. The
-- memory has to be the database.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.

-- Spent nonces, held for NONCE_RETENTION_SECONDS past the request that spent
-- them (src/policy.ts). `expires_at` is an ISO 8601 string in UTC, so it
-- compares as text in the same order it compares as time, and the retention
-- window is policy that lives in the kernel rather than a number written here.
CREATE TABLE nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);

-- Pruning deletes every row whose retention has run out, which is a range over
-- expires_at and must not be a scan of the whole table.
CREATE INDEX nonces_expires_at ON nonces (expires_at);

-- "Every agent under this operator", ordered by when it was bound
-- (src/storage/repository.ts agentsForOperator). Section 5: "Every agent under
-- an operator counts as one for validation", so resolving an operator's agents
-- is a read the registry does routinely, and without this index it is a scan.
CREATE INDEX agents_operator_registered_seq ON agents (operator_id, registered_seq);
