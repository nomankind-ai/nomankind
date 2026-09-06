# nomankind

nomankind checks where a fact came from before an AI model learns it, and keeps the proof.

Models learn from the world, and every fact they take in came from somewhere. Today that somewhere is usually figured out later, if at all: audits try to trace what a model was trained on after the weights already hold it, and mostly they cannot. nomankind works the other way around. Before a fact can be learned from, its source is captured and hashed, three independent operators check it and sign, and the record is sealed with a timestamp. Only then is it offered to a model. Proof first, use second.

It starts with one area, the AI ecosystem, because that is where models fall behind fastest. A model is frozen at its training cutoff, but prices, rate limits, model behavior, and APIs keep changing. nomankind is a running, cited record of those changes: an append-only log of small facts, each verified by three operators who are neither the submitter nor a model provider, each hashed and sealed so any edit shows, and each dated so you can see how fresh it is.

Built on the [1F916 protocol](https://1f916.org) for agent identity and sealed logs. Learn more at [nomankind.ai](https://nomankind.ai).

## Primary use: feeding continual learners

The log is built first for models that train from it. A continual learner pulls every change since its last sync as a sealed delta stream, in the exact order it was sealed, so two models syncing from the same position take in the same sequence and can prove it. Facts that were overturned travel as explicit unlearn signals. Each fact carries its evidence and a last-confirmed date, so a learner can weight it, hold it, or skip it. A drift attestation lets independent operators certify in public that a model's beliefs still match the record. Every fact a learner takes from the stream arrives with its chain of custody complete: source hash, three signatures, seal time, reproduction counts where a predicate exists, and every dispute since. This is provenance of the slice a model learned from the log, not of its training set.

## Verifiable now, and empirical where it can be

Verified means three independent operators confirmed that the source says what the entry says (two while the trusted pool is still under ten operators), and the entry stays open to dispute forever. For a fact that rests only on a cited page, that is provenance, and the log says so.

Verification is the floor. Every entry carries an evidence tier in its signed core. A stated entry rests on a document. An observed entry rests on a measurement: a metered price call, a probe to a rate limit, an endpoint returning its deprecation error, a reproduced model behavior. The submitter freezes the test and its receipt with the claim, validators first judge whether the test decides the claim and then run it themselves under a published n-of-k rule, and each records its own receipt. Behavior and misbehavior entries are observed by rule. Observed entries earn a larger read share, so the operators who measure are paid more than the operators who copy. That is the path from verification toward truth: where a claim can be measured, the record moves past "a source said it" toward "this was observed to hold," fact by fact. Where it cannot, the entry stays stated and honest about it. The tier tells a reader which kind of entry they are holding. A confidence field derived from the receipts is planned; it stays null until there is enough dispute history to calibrate it, and its raw inputs are exposed in the meantime.

## Also for frozen models

A model that reads at inference time gets the fastest true fact on wake: one signed entry with a receipt, no vendor page and no injection surface.

## The record outlives the source

Sources rot. Labs edit their own documentation quietly, pages move, and the page a fact came from can be changed or taken down. nomankind captures what a source said at the moment it was cited, hashes it, and seals it into a witnessed log. Even if the original page is later edited or destroyed, the sealed, dated, independently verified record of what it said still stands, and anyone can check it offline. A legal takedown can remove a served copy of a page, but not the hash, the signatures, or the proof of what it once said.

That guarantee reaches well past the AI ecosystem. The mechanism generalizes to any domain with checkable predicates, and degrades to provenance-only where they do not exist: who said it, what it said at capture, who confirmed it, when it was sealed. Take a work of art: if the piece is lost or destroyed, that same record, who made it, what it was, and who independently vouched for it, still stands on its own. nomankind keeps its scope narrow, the AI ecosystem, by design. New domains come only after this one is saturated.

## What's in this repo

- [`paper/SUMMARY.md`](paper/SUMMARY.md): the design in one page.
- [`paper/WHITEPAPER.md`](paper/WHITEPAPER.md): the design in full (v1.5).
- [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json): the entry schema (v0.6). The single copy; the code reads this file.
- [`schema/nomankind-entry-example.json`](schema/nomankind-entry-example.json): a worked example entry.
- [`schema/nomankind-snapshot-normalization-v1.md`](schema/nomankind-snapshot-normalization-v1.md): the norm-v1.1 hashing rule.
- [`docs/POC-RETROSPECTIVE.md`](docs/POC-RETROSPECTIVE.md): what the retired proof of concept taught.
- [`docs/decisions/`](docs/decisions/): short numbered records of decisions that are not derivable from the code.

The application (kernel package, Worker, web UI, infrastructure) is built here from the spec; its layout lands in this repo as it is built. See [CONTRIBUTING.md](CONTRIBUTING.md) for how the work is organized.

## Repositories

- **nomankind** (this repo): code, entry schema, and the whitepaper. Apache-2.0.
- **[log](https://github.com/nomankind-ai/log)**: the append-only log mirror that continual learners read as a delta stream (entries, events, hashes, indexes). CC0, forkable on its own.

## License

Code is licensed under [Apache-2.0](LICENSE). The data (entries, events, hashes, indexes, the log itself) is dedicated to the public domain under CC0 and lives in the separate [log](https://github.com/nomankind-ai/log) repository.

## Status

The design is specified (whitepaper v1.5, schema v0.6). A proof of concept of the core mechanics was built and retired in September 2026: an append-only signed hash-chained log, every status derived from events, consensus with the small-pool rule, evidence tiers with n-of-k acceptance, Merkle seals with witnesses, a read API with signed receipts, and an offline verifier, all under test. Its lessons are in the retrospective. The application is now being built from the spec for `demo.nomankind.ai` (staging) and `app.nomankind.ai` (production); progress is tracked in the issues labeled `roadmap`.

The first public milestone is unchanged and falsifiable: three verified operators, none of them the maintainer's, promoting a seeded entry to verified. See the Limitations section of the whitepaper for what is still open.
