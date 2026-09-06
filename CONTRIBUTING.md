# Contributing to nomankind

nomankind is open by design. The code, the entry schema, and the log format are public, so that if the project ever breaks its own rules, anyone can fork the whole record and keep going. Contributions are welcome on that basis.

## Ways to contribute

- **Code and docs.** Open a pull request. The maintainer reviews and merges. Every merge to `main` deploys the staging environment at `demo.nomankind.ai`; production at `app.nomankind.ai` deploys from a tagged release. Keep changes focused and tested.
- **Entries.** Facts are submitted as signed entries that conform to [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json). An entry states what a cited primary source said or what a reproducible transcript shows. It never states a characterization or an opinion. Each entry carries a citation and a snapshot hash computed by the [norm-v1.1 rule](schema/nomankind-snapshot-normalization-v1.md).
- **Disputes and corrections.** A challenge is itself an entry in the `correction` category, with its own citation. Evidence decides the outcome, and unfounded challenges cost standing.

## Ground rules

- One atomic, cited claim per entry. If you cannot cite it, it does not belong.
- No opinions, rankings, or scores. nomankind records transactional facts, not judgments.
- No model provider may act as a maintainer, funder, or trusted validator. Neutrality is the point.
- Keep the tone neutral. The log records what a source said and lets readers decide what it means.

## How the work is organized

- **One repository.** The spec (`paper/`, `schema/`) and the application live here. The schema has exactly one copy, `schema/nomankind-entry-schema.json`, and the code reads it; nothing is copied by hand.
- **Issues are the tracker.** The roadmap is the set of issues labeled `roadmap`, one per step. Each milestone inside a step is its own issue, closed by the pull request that delivers it.
- **One pull request per milestone.** The PR description is the session note: what was built, how it was verified, what was deferred. `main` is protected; a PR merges only with green CI and the maintainer's review.
- **Decisions are written down.** Anything not derivable from the code goes in `docs/decisions/` as a short numbered record: the decision, the reason, the alternatives passed over.
- **Rules carried over from the proof of concept.** Policy numbers live in one policy module and nowhere else. Status and every derived field are recomputed from events, never set directly. Time is injected wherever it matters, so tests are deterministic. Field names come from the schema exactly. See [`docs/POC-RETROSPECTIVE.md`](docs/POC-RETROSPECTIVE.md) for the bugs these rules prevent.

## Licensing of contributions

By contributing, you agree that code is licensed under [Apache-2.0](LICENSE) and that log data (entries, events, hashes, indexes) is dedicated to the public domain under CC0.

See the [whitepaper](paper/WHITEPAPER.md) for the full design, evidence rules, and governance.
