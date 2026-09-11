# Contributing to nomankind

nomankind is open by design. The code, the entry schema, and the log format are public, so that if the project ever breaks its own rules, anyone can fork the whole record and keep going. Contributions are welcome on that basis.

## Ways to contribute

- **Code and docs.** Open a pull request. The maintainer reviews and merges. Every merge to `main` deploys the site, so keep changes focused and tested.
- **Entries.** Facts are submitted as signed entries that conform to [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json). An entry states what a cited primary source said or what a reproducible transcript shows. It never states a characterization or an opinion. Each entry carries a citation and a snapshot hash computed by the [norm-v1.1 rule](schema/nomankind-snapshot-normalization-v1.md).
- **Disputes and corrections.** A challenge is itself an entry in the `correction` category, with its own citation. Evidence decides the outcome, and unfounded challenges cost standing.

## Ground rules

- One atomic, cited claim per entry. If you cannot cite it, it does not belong.
- No opinions, rankings, or scores. nomankind records transactional facts, not judgments.
- No model provider may act as a maintainer, funder, or trusted validator. Neutrality is the point.
- Keep the tone neutral. The log records what a source said and lets readers decide what it means.

## Running the tests

`npm test` runs the whole suite and `npm run typecheck` checks the types. On macOS the suite runs two workers wide rather than one per core, because it would otherwise run out of loopback ports: the storage tests reach a real D1 and R2 through wrangler's `getPlatformProxy`, and miniflare closes the connection after every proxied binding call, so each call leaves a socket in `TIME_WAIT` for about thirty seconds. Measured on an Apple laptop against the 16,384 ephemeral ports macOS hands out: one storage file alone leaves about 1,100 sockets, a full run at default width leaves about 15,200 to 15,800 and fails a handful of storage-backed files with `connect EADDRNOTAVAIL`, four workers leaves about 8,700, and two workers leaves about 2,900 and takes about 105 seconds against 32 at full width. The cap is keyed to `process.platform` in `vitest.config.ts`, so Linux and CI keep every core and are unaffected. Running a single test file is never capped in practice and always passes.

## Licensing of contributions

By contributing, you agree that code is licensed under [Apache-2.0](LICENSE) and that log data (entries, events, hashes, indexes) is dedicated to the public domain under CC0.

See the [whitepaper](paper/WHITEPAPER.md) for the full design, evidence rules, and governance.
