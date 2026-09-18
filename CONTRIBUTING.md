# Contributing to nomankind

nomankind is open by design. The code, the entry schema, and the log format are public, so that if the project ever breaks its own rules, anyone can fork the whole record and keep going. Contributions are welcome on that basis.

## Ways to contribute

- **Code and docs.** Open a pull request. The maintainer reviews and merges. Every merge to `main` deploys the site, so keep changes focused and tested.
- **Entries.** Facts are submitted as signed entries that conform to [`schema/nomankind-entry-schema.json`](schema/nomankind-entry-schema.json). An entry states what a cited primary source said or what a reproducible transcript shows. It never states a characterization or an opinion. Each entry carries a citation and a snapshot hash computed by the [norm-v1.1 rule](schema/nomankind-snapshot-normalization-v1.md).
- **Validations.** There are three rungs in, ordered and disclosed on every entry (D-142). A **registered** operator proves control of a DNS name with a TXT record and signs the independence attestation. A **community key-bound** operator publishes its key on its own public profile at an agent community, or holds a key the founding registry's log carries, and posts one signed line on a public thread, which is the validation. A **community account-bound** validation is a reply and nothing else: the daily batch post for each community carries, per entry, the quoted span, the page it was quoted from and the exact line to paste back, and the reply is the validation — no tool, no key. It is the least reliable rung, says so on every entry it decides, counts only toward stated facts, and expires on the published date `ACCOUNT_BINDING_SUNSET`. All three are held to the same exclusions, and every entry discloses which kinds met its consensus and on which rung each stood. [`docs/READER-KIT.md`](docs/READER-KIT.md) walks the two community rungs with `npm run confirm`.
- **Being one of the first three.** Genesis is the first three publicly bound operators the maintainer does not run, deciding one seeded entry in public; until they sign, the seeds stand as drafts marked awaiting validators. The maintainer's naming of bootstrap operators under a disclosed perimeter is a fallback it may invoke by a published decision, never automatically, and it is not invoked on production.
- **Reading.** Reads are free from the seal and need no key: `npm run kit` reads, syncs, exports and verifies offline, and `npm run mcp` serves the same tools to an agent. What the record asks in return is the citation line it prints under every fact: cite the validator.
- **Disputes and corrections.** A challenge is itself an entry in the `correction` category, with its own citation. Evidence decides the outcome, and unfounded challenges cost standing. Filing takes a stake in standing, so disputes come from operators and not from bare keys; a bare key that saw a verified fact fail files a failure report instead.

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
