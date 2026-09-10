-- 0012_domains: the domain an entry belongs to, and the domains an operator is
-- attested in (M22b, decision D-071).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0011 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. `entries.domain` is a copy of the signed
-- core's eighteenth key, and every row of `operator_domains` is a copy of what
-- an `operator_registered` or `operator_joined_domain` event already sealed:
-- drop both and the same answers come back by replaying the log (src/core.ts's
-- `domainOf`, src/derive.ts's `operatorDomainsAt`). They exist because the
-- questions they answer -- "the pricing entries of this domain, newest first",
-- "is this operator attested in the domain of the entry it wants to judge" --
-- cannot be asked of the events table without scanning it.

-- Whitepaper Section 3, "The log": the mechanism does not care about the
-- domain. The tables do (schema/nomankind-domain-registry-v1.md), so the domain
-- travels beside `subject` and `category` -- the two columns it is the same kind
-- of thing as, all three copies of signed core keys.
--
-- NOT NULL with a default rather than a nullable column, and backfilled below
-- for the rows already stored: every entry belongs to a domain, and a v0.6 core
-- that names none belongs to ai-ecosystem, which was the only domain there was
-- when it was signed. The default is what the column means for a legacy row and
-- never a guess about a new one -- src/storage/repository.ts writes the value
-- `domainOf` read off the core, for every row it writes.
ALTER TABLE entries ADD COLUMN domain TEXT NOT NULL DEFAULT 'ai-ecosystem';

-- Backfill for rows written before this migration: the domain out of the stored
-- entry's own JSON when it carries one, ai-ecosystem when it does not. Written
-- as an UPDATE rather than left to the column default so the two paths agree --
-- a row whose entry_json already says v0.7 must not read as the default.
UPDATE entries
   SET domain = COALESCE(json_extract(entry_json, '$.domain'), 'ai-ecosystem');

-- "The entries of this domain, by status, newest sealed position first": the
-- entries page's chip group and the home page's counters, filtered by domain.
-- The same shape as the listings 0001 already serves, with the domain leading
-- because it is the outermost narrowing the page applies.
CREATE INDEX entries_domain_status_seq ON entries (domain, status, submitted_seq);

-- Which domains an operator is attested in.
--
-- Decision D-071: the independence attestation is per domain, so eligibility is
-- too. Registration binds an operator to its first domain's attestation and a
-- join carries a later domain's, each sealed as an event; this table is the
-- index into those events, one row per (operator, domain).
--
-- `seq` is the position of the event that put the row there -- the registration
-- or the join -- so "was this operator attested in this domain at that
-- position" is a comparison rather than a fold. `attestation_json` is the signed
-- attestation exactly as the event carries it, kept so the operator page can
-- show which version was signed for which domain without reading the log.
CREATE TABLE operator_domains (
  operator         TEXT    NOT NULL,
  domain           TEXT    NOT NULL,
  seq              INTEGER NOT NULL,
  attestation_json TEXT,
  PRIMARY KEY (operator, domain)
);

-- Every operator registered before this migration was registered under the only
-- domain there was, with the attestation its registration event carried. The
-- attestation lives on the `agent_bound` event of the agent that signed it; the
-- operator row's own JSON carries it too where the Worker stored it, which is
-- what this reads, and a row that carries none backfills with a null rather than
-- with an invented record.
INSERT INTO operator_domains (operator, domain, seq, attestation_json)
SELECT id,
       'ai-ecosystem',
       registered_seq,
       json_extract(operator_json, '$.attestation')
  FROM operators;

-- "Who is attested in this domain?": the draw's exclusion list, built per domain
-- (src/assign.ts takes the pool and the caller passes everyone not attested in
-- the entry's domain). The primary key already orders by (operator, domain) and
-- cannot answer this one, so the domain leads its own index.
CREATE INDEX operator_domains_domain ON operator_domains (domain, operator);
