-- 0006_sealing: what a seal carries once it is real, and the day's read.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0005 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Whitepaper, "Lifecycle of an entry" (Seal): the seal's fingerprint goes to
-- nomankind's agent log at the founding registry, and the witnesses countersign
-- the registry head it lands under. What the registry returned when it accepted
-- the fingerprint is evidence, so it is stored beside the seal rather than
-- recomputed — nothing here can recompute another party's receipt.
--
-- Null until the registry accepted it, and null forever on the demo, where the
-- mock adapter has no registry to submit to. Outside the seal hash, exactly
-- like witnesses_json: both are gathered after the seal exists, and a hash that
-- moved when they arrived would break every seal chained after it.
ALTER TABLE seals ADD COLUMN registry_json TEXT;

-- "Which seals were sealed on this UTC day?": the anchor step's one read, and
-- the only question about seals that starts from a date rather than from a seq.
-- sealed_at is the injected clock's ISO instant, so a day is the half-open text
-- range ['<day>T', '<day>U') and this index seeks it (src/storage/repository.ts,
-- sealsSealedOn).
CREATE INDEX seals_sealed_at ON seals (sealed_at);
