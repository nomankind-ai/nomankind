-- 0003_captures: the index into the snapshot archive.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 and 0002 are closed; this file
-- adds and never reshapes.
--
-- The norm rule's step 2 (Archive) puts the raw capture and its sidecar in R2 at
-- the hash of the body bytes. R2 answers "give me this address"; it does not
-- answer "which capture backs this entry's snapshot_hash", and that is the
-- question every reader of an entry asks. This table is that answer and nothing
-- more: the bytes stay in the archive, and a row here is the pointer to them.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.

-- One row per capture an entry rests on.
--
-- `role` is "snapshot" for the capture whose hash is the entry's snapshot_hash
-- (the cited page, or the frozen transcript artifact of a behavior entry) and
-- "receipt" for the observation receipt whose hash is observation.receipt_hash.
-- An entry has at most one of each, which is what the primary key says.
--
-- `content_hash` is the hash the entry carries, computed under the norm rule;
-- `archive_hash` is the R2 key, which is the hash of the raw bytes. For an HTML
-- page the two differ — one is over the extracted content, the other over the
-- body — and for a PDF or a binary they are the same value. `norm_version` is
-- the version those hashes were computed under, copied from the entry, so a
-- capture stays readable when a later version moves the rule.
CREATE TABLE captures (
  entry_id     TEXT    NOT NULL,
  role         TEXT    NOT NULL,
  content_hash TEXT    NOT NULL,
  archive_hash TEXT    NOT NULL,
  norm_version TEXT    NOT NULL,
  kind         TEXT    NOT NULL,
  media_type   TEXT    NOT NULL,
  size         INTEGER NOT NULL,
  fetched_at   TEXT    NOT NULL,
  PRIMARY KEY (entry_id, role)
);

-- "Which capture is this hash?": the public read behind GET /captures/{hash}.
-- Ordered by when it was captured and then by entry, so the answer to a hash
-- two entries cite is the earliest capture of it and is the same answer every
-- time, and so the lookup is an index seek rather than a scan.
CREATE INDEX captures_content_hash ON captures (content_hash, fetched_at, entry_id);
