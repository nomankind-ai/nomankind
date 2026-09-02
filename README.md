# nomankind

nomankind is verifiable training provenance for AI models that keep learning, demonstrated on a changelog of the AI ecosystem.

A model that learns from the world takes facts on someone's word. Today, whose word is worked out after the fact, if at all: dataset audits try to reconstruct where training data came from once the weights already hold it, and mostly they cannot. nomankind establishes provenance before a fact is used. Each fact enters with its source frozen, its verification signed by named operators outside the submitter's control, and its seal timestamped, and only then is it offered to be learned from.

The first domain is the AI ecosystem, because models are worst at it. A model is frozen at its training cutoff, but the ecosystem it runs in is not. A continual-learning model needs to know what changed since its weights were cut, from a source it can check instead of a vendor it has to trust. nomankind is that source: an append-only log of small, cited facts about the AI ecosystem (releases, deprecations, pricing, rate limits, behavior changes, outages, and documented misbehavior), each verified by three agents run by three independent operators, none of them a model provider. Every entry is hashed and sealed into a witnessed log, so any change leaves proof, and carries a last-confirmed date, so staleness is visible.

Built on the [1F916 protocol](https://1f916.org) for agent identity and sealed logs. Learn more at [nomankind.ai](https://nomankind.ai).

## Primary use: feeding continual learners

The log is built first for models that train from it. A continual learner pulls every change since its last sync as a sealed delta stream, in the exact order it was sealed, so two models syncing from the same position take in the same sequence and can prove it. Facts that were overturned travel as explicit unlearn signals. Each fact carries its evidence and a last-confirmed date, so a learner can weight it, hold it, or skip it. A drift attestation lets independent operators certify in public that a model's beliefs still match the record. Every fact a learner takes from the stream arrives with its chain of custody complete: source hash, three signatures, seal time, reproduction counts where a predicate exists, and every dispute since. This is provenance of the slice a model learned from the log, not of its training set.

## Verifiable, not proven

Verified here means three independent operators confirmed the source said what the entry says, and the entry stays open to dispute forever. That is a receipt chain, not proof of truth. The paper calls this verifiable provenance and avoids "proof of" on purpose: the phrase says what a reader can check, not what to believe.

## Also for frozen models

A model that reads at inference time gets the fastest true fact on wake: one signed entry with a receipt, no vendor page and no injection surface.

## The record outlives the source

Sources rot. Labs edit their own documentation quietly, pages move, and the page a fact came from can be changed or taken down. nomankind captures what a source said at the moment it was cited, hashes it, and seals it into a witnessed log. Even if the original page is later edited or destroyed, the sealed, dated, independently verified record of what it said still stands, and anyone can check it offline. A legal takedown can remove a served copy of a page, but not the hash, the signatures, or the proof of what it once said.

That guarantee reaches well past the AI ecosystem. The mechanism generalizes to any domain with checkable predicates, and degrades to provenance-only where they do not exist: who said it, what it said at capture, who confirmed it, when it was sealed. nomankind keeps its scope narrow, the AI ecosystem, by design. New domains come only after this one is saturated.

## What's in this repo

- [`paper/WHITEPAPER.md`](paper/WHITEPAPER.md): the design in full (v1.1).
- [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json): the entry schema (v0.5).
- [`schema/nomankind-entry-example.json`](schema/nomankind-entry-example.json): a worked example entry.
- [`schema/nomankind-snapshot-normalization-v1.md`](schema/nomankind-snapshot-normalization-v1.md): the norm-v1 hashing rule.

## Repositories

- **nomankind** (this repo): code, entry schema, and the whitepaper. Apache-2.0.
- **[log](https://github.com/nomankind-ai/log)**: the append-only log mirror that continual learners read as a delta stream (entries, events, hashes, indexes). CC0, forkable on its own.

## License

Code is licensed under [Apache-2.0](LICENSE). The data (entries, events, hashes, indexes, the log itself) is dedicated to the public domain under CC0 and lives in the separate [log](https://github.com/nomankind-ai/log) repository.

## Status

The design is specified and the entry schema is defined. The first milestone is public and falsifiable: three verified operators, none of them the maintainer's, promoting a seeded entry to verified. See the Limitations section of the whitepaper for what is still open.
