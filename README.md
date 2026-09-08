# nomankind

nomankind checks where a fact came from before an AI model learns it, and keeps the proof.

Models learn from the world, and every fact they take in came from somewhere. Today that somewhere is usually figured out later, if at all: audits try to trace what a model was trained on after the weights already hold it, and mostly they cannot. nomankind works the other way around. Before a fact can be learned from, its source is captured and hashed, three independent operators check it and sign, and the record is sealed with a timestamp. Only then is it offered to a model. Proof first, use second.

It starts with one area, the AI ecosystem, because that is where models fall behind fastest. A model is frozen at its training cutoff, but prices, rate limits, model behavior, and APIs keep changing. nomankind is a running, cited record of those changes: an append-only log of small facts, each verified by three operators who are neither the submitter nor a model provider, each hashed and sealed so any edit shows, and each dated so you can see how fresh it is.

Built on the [1F916 protocol](https://1f916.org) for agent identity and sealed logs. Learn more at [nomankind.ai](https://nomankind.ai).

## Primary use: feeding continual learners

The log is built first for models that train from it. A continual learner pulls every change since its last sync as a sealed delta stream, in the exact order it was sealed, so two models syncing from the same position take in the same sequence and can prove it. Facts that were overturned travel as explicit unlearn signals. Each fact carries its evidence and a last-confirmed date, so a learner can weight it, hold it, or skip it. A drift attestation lets independent operators certify in public that a model's beliefs still match the record. Every fact a learner takes from the stream arrives with its chain of custody complete: source hash, three signatures, seal time, reproduction counts where a predicate exists, and every dispute since. This is provenance of the slice a model learned from the log, not of its training set.

## Verifiable now, and empirical where it can be

Verified means three independent operators confirmed that the source says what the entry says (two while the trusted pool is still under ten operators), and the entry stays open to dispute forever. For a fact that rests only on a cited page, that is provenance, and the log says so. Anyone can check that offline with two files and one script: `npm run verify -- <entry.json> <log.json>` exits 0 when the entry checks out and 1 with the named diffs when it does not.

The application itself runs as a Cloudflare Worker with the log and everything derived from it in D1. `npm run dev` serves it locally, with a health endpoint at `/health` that reports whether the Worker booted and whether its database answers. Schema changes are numbered SQL files under `migrations/`, applied in name order by wrangler and never edited after merge.

Every merge to main deploys the demo environment at demo.nomankind.ai through the Deploy demo action, which typechecks, runs the tests, applies the D1 migrations, and only then puts the Worker live. An annotated tag `v<major>.<minor>.<patch>` on main deploys production at app.nomankind.ai, and the apex nomankind.ai, through the Deploy production action. Every pull request gets a preview version of the demo environment, with its URL posted on the pull request. The actions need two repository secrets, `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`; no deploy is ever run by hand.

Verification is the floor. Every entry carries an evidence tier in its signed core. A stated entry rests on a document. An observed entry rests on a measurement: a metered price call, a probe to a rate limit, an endpoint returning its deprecation error, a reproduced model behavior. The submitter freezes the test and its receipt with the claim, validators first judge whether the test decides the claim and then run it themselves under a published n-of-k rule, and each records its own receipt. Behavior and misbehavior entries are observed by rule. Observed entries earn a larger read share, so the operators who measure are paid more than the operators who copy. That is the path from verification toward truth: where a claim can be measured, the record moves past "a source said it" toward "this was observed to hold," fact by fact. Where it cannot, the entry stays stated and honest about it. The tier tells a reader which kind of entry they are holding. A confidence field derived from the receipts is planned; it stays null until there is enough dispute history to calibrate it, and its raw inputs are exposed in the meantime.

## Also for frozen models

A model that reads at inference time gets the fastest true fact on wake: one signed entry with a receipt, no vendor page and no injection surface.

## The record outlives the source

Sources rot. Labs edit their own documentation quietly, pages move, and the page a fact came from can be changed or taken down. nomankind captures what a source said at the moment it was cited, hashes it, and seals it into a witnessed log. Even if the original page is later edited or destroyed, the sealed, dated, independently verified record of what it said still stands, and anyone can check it offline. A legal takedown can remove a served copy of a page, but not the hash, the signatures, or the proof of what it once said.

That guarantee reaches well past the AI ecosystem. The mechanism generalizes to any domain with checkable predicates, and degrades to provenance-only where they do not exist: who said it, what it said at capture, who confirmed it, when it was sealed. Take a work of art: if the piece is lost or destroyed, that same record, who made it, what it was, and who independently vouched for it, still stands on its own. nomankind keeps its scope narrow, the AI ecosystem, by design. New domains come only after this one is saturated.

## What's in this repo

- [`paper/SUMMARY.md`](paper/SUMMARY.md): the design in one page.
- [`paper/WHITEPAPER.md`](paper/WHITEPAPER.md): the design in full (v1.5).
- [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json): the entry schema (v0.6).
- [`schema/nomankind-entry-example.json`](schema/nomankind-entry-example.json): a worked example entry.
- [`schema/nomankind-snapshot-normalization-v1.md`](schema/nomankind-snapshot-normalization-v1.md): the norm-v1.2 hashing rule.

The operator registry is served by the Worker: `POST /operators` to join, `POST /genesis` for the maintainer's one-time naming of the first trusted operators, and `GET /operators`, `GET /operators/{id}` and `GET /agents/{id}` to read the result. Joining takes the whitepaper's three steps — publish a TXT record at `_nomankind.<your domain>` carrying your 1F916 agent id, complete payout onboarding, and sign the provider-independence attestation with your 1F916 key — and the DNS check is real everywhere, while payout onboarding is mocked on demo until the payment provider is wired. Locally, apply the migrations first with `npx wrangler d1 migrations apply nomankind-local --local`, because `npm run dev` starts on an empty local database and these routes answer 503 `storage_unreachable` until the schema is there.

Entries are submitted to the same Worker. `POST /entries` takes `{entry, receipt}`, where `entry` is the seventeen immutable core keys plus the author's `signature` over their JCS canonical form and `receipt` is the observation receipt object, sent only when the core carries an `observation`. The request itself is signed like every other write: the four `x-nomankind-*` headers carrying the agent id, a timestamp, a single-use nonce, and an Ed25519 signature over the method, the path and the canonical body. Anyone may submit with a bare agent key, and the entry then names no operator; a key bound to a registered operator must name that operator in its signed core. The Worker fetches the citation itself under the norm-v1.2 rule — fixed headers, at most five redirects, a thirty-second timeout, the final URL recorded — and refuses the submission unless the hash of what it fetched is the `snapshot_hash` the author signed. Refusals are 401 for a bad request signature or a bad entry signature, 403 when the signing key is not the author, 409 for an entry already in the log, and 422 for everything the entry itself gets wrong: `snapshot_mismatch`, `needs_javascript` for a page whose content only a browser could show, `invalid_json`, `unsupported_citation`, the fetch refusals (`bad_status`, `too_large`, `too_many_redirects`, `timeout`, `fetch_failed`), a supersession that does not hold, a missing or mismatched receipt, and `schema_invalid` with the failing fields. Nothing is written unless every check passes. On success the answer is 201 with the derived entry, which is `draft`: status is recomputed from the log and is never sent in.

`GET /entries/{id}` returns that entry. The raw capture is public too: `GET /captures/{hash}` returns the bytes that were archived under a `snapshot_hash` or a `receipt_hash`, with the archive address in `x-nomankind-archive-hash`, and `GET /captures/{hash}/sidecar` returns the norm rule's `{final_url, status, headers, fetched_at, fetcher}` record of the fetch. A capture is served as evidence rather than as a page — its stored media type, but `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; sandbox` — because anyone can submit with a bare key and the bytes are a stranger's. The captures live in R2 under the `CAPTURES` binding — `nomankind-local-captures`, `nomankind-demo-captures`, `nomankind-production-captures` — content addressed and written once, so a capture is evidence rather than a cache.

Two build notes. `npm run gen:validator` recompiles `src/schema-validator.generated.ts` from the entry schema and must be rerun whenever the schema changes: Workers forbid building a validator at run time, so the schema is compiled ahead of time and the committed file is checked against a fresh generation. And production has no maintainer key configured, so `POST /entries` there answers 503 `fetcher_not_configured` until M25: the sidecar names the 1F916 identity that fetched, and an unconfigured deployment has none to name.

## Repositories

- **nomankind** (this repo): code, entry schema, and the whitepaper. Apache-2.0.
- **[log](https://github.com/nomankind-ai/log)**: the append-only log mirror that continual learners read as a delta stream (entries, events, hashes, indexes). CC0, forkable on its own.

## License

Code is licensed under [Apache-2.0](LICENSE). The data (entries, events, hashes, indexes, the log itself) is dedicated to the public domain under CC0 and lives in the separate [log](https://github.com/nomankind-ai/log) repository.

## Status

The design is specified and the entry schema is defined. The first milestone is public and falsifiable: three verified operators, none of them the maintainer's, promoting a seeded entry to verified. See the Limitations section of the whitepaper for what is still open.
