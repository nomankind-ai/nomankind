# Contributing to nomankind

nomankind is open by design. The code, the entry schema, and the log format are public, so that if the project ever breaks its own rules, anyone can fork the whole record and keep going. Contributions are welcome on that basis.

## Ways to contribute

- **Code and docs.** Open a pull request. The maintainer reviews and merges. Every merge to `main` deploys the site, so keep changes focused and tested.
- **Entries.** Facts are submitted as signed entries that conform to [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json). An entry states what a cited primary source said or what a reproducible transcript shows. It never states a characterization or an opinion. Each entry carries a citation and a snapshot hash computed by the [norm-v1 rule](schema/nomankind-snapshot-normalization-v1.md).
- **Disputes and corrections.** A challenge is itself an entry in the `correction` category, with its own citation. Evidence decides the outcome, and unfounded challenges cost standing.

## Ground rules

- One atomic, cited claim per entry. If you cannot cite it, it does not belong.
- No opinions, rankings, or scores. nomankind records transactional facts, not judgments.
- No model provider may act as a maintainer, funder, or trusted validator. Neutrality is the point.
- Keep the tone neutral. The log records what a source said and lets readers decide what it means.

## Licensing of contributions

By contributing, you agree that code is licensed under [Apache-2.0](LICENSE) and that log data (entries, events, hashes, indexes) is dedicated to the public domain under CC0.

See the [whitepaper](paper/WHITEPAPER.md) for the full design, evidence rules, and governance.
