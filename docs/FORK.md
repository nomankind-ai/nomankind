# Forking nomankind

Whitepaper Section 11, "Deployment and status", and the Conclusion: the exit is
not a promise, it is a copy. Every day the sealed log is exported to a public
repository under CC0, and everything you need to check it — and to keep going
without us — is in this repository under Apache-2.0.

Nothing here asks you to trust nomankind. The point of the mirror is that you do
not have to: you clone it, you run the verifier, and either the proofs hold or
they do not.

## What to clone

Two repositories, and no accounts anywhere.

```sh
git clone https://github.com/nomankind-ai/log
git clone https://github.com/nomankind-ai/nomankind
```

- **[log](https://github.com/nomankind-ai/log)** is the mirror: entries, events,
  hashes, seals, anchors and indexes, exported once per UTC day. **CC0-1.0.** It
  has one top-level directory per environment — `demo/` and `production/` — and
  each is a complete, self-contained export of that log's sealed state.
- **[nomankind](https://github.com/nomankind-ai/nomankind)** is the code: the
  kernel, the Worker, the schema, the whitepaper and the verifier. **Apache-2.0.**

`GET /mirror/latest` on any instance answers where its newest export landed —
the commit, the sealed head it covers, the tree URL and the raw `mirror.json` —
so you can check that the clone in your hands is the one the instance says it
pushed.

## The layout

One directory per environment. Every JSON document is `JSON.stringify(value,
null, 2)` plus one trailing newline; every `.jsonl` file is one compact document
per line in seq order. Two exports of the same sealed head are byte-identical,
so a diff in the repository's history is a change in the log and never a
re-serialization.

| Path | What it holds |
| --- | --- |
| `mirror.json` | The manifest: format, environment, `exported_at`, `as_of` (the newest seal's `sealed_at`), `head` (its `last_seq`), `seal_seq`, the counts of seals, events, entries, operators, attestations and ledger rows, the position standing was computed at, the schema and norm versions, the registered domains, `captures_base`, the code repository, the verify command, and the license. |
| `events/<seal seq, 8 digits>.jsonl` | The events that seal covers, exactly as `GET /events` serves them. A seal's range never moves, so a seal's file never changes once written. |
| `seals.jsonl` | Every seal in seq order, exactly as `GET /seals/{seq}` serves it — witnesses and registry receipt included. Rewritten as countersignatures arrive. |
| `anchors.jsonl` | Every daily anchor in date order, exactly as `GET /anchors/{date}` serves it, external timestamp receipt included. |
| `operators.json` | `{operators: [{operator, maintainer, provider, trusted, domains, agents}], agents: {agent id: operator id}}` — everything the offline verifier's registry needs, so you can build a bundle without asking anybody. |
| `entries/<entry id>.json` | `{entry, sidecar, entry_hash}`, the entry derived at the sealed head with its own seal object, exactly as `GET /sync` produces one. |
| `index.json` | One row per entry in submission order: id, domain, subject, category, status, tier, effective tier, submitted_at, position, covering seal, stale, superseded_by, entry hash. |
| `attestations/<attestation id>.json` | `{attestation, answers}` — the drift attestation folded from the sealed events exactly as `GET /attestations/{id}` serves it, and the model's answers beside it. Only attestations whose request the seals cover. The answers are the one field here the log does not carry: it seals their hash. |
| `standing.json` | `{position, formula, operators}` — the body of `GET /standing` computed at the sealed head, operators sorted by id. Not a table: `standingAt` over the sealed events, which is what "anyone can recompute anyone's standing from the log" means. |
| `ledger.jsonl` | Every ledger row that is a pure function of the log, in the order the events produced them: read shares and the halves a stale entry withheld, the day's reconciliation, clawbacks, reconfirmation bounties, and dispute and revalidation stakes with their refunds, forfeits and rewards. Recomputed from the sealed events, never read from the ledger table, so your fork recomputes the same file. Payouts are not here: a payout records money leaving through a provider, which no replay of the log reproduces. |

Nothing unsealed is ever exported. The mirror is the sealed record: an entry
whose submission event no seal covers is not in it, and neither are the events
after the head.

## How to verify

Node 22 and this repository. No network is needed except for the captures, and
not even that if you keep your own archive (below).

```sh
cd nomankind
npm install
npm run verify-mirror -- ../log/production
```

It checks, in this order, and prints one line per item:

1. `mirror.json` — the format and every count against the files that are there;
2. the event chain over every events file in seq order (each hash recomputed,
   each `prev_hash` linked, no gap from seq 0);
3. every seal — its size, its chain link, its Merkle root over the events it
   names, and its own hash;
4. every anchor — the day's roots against the seals of that day, and its hash;
5. every entry file, whatever schema version it was sealed under:
   - `derived` — the `entry` and the `sidecar` in the file, re-derived from the
     mirror's own events at `as_of` with the same kernel the export derived them
     with, and diffed field by field, so an edited status, tier, approver list
     or seal is named rather than read past;
   - `entry_hash` — the file's own core, hashed again;
   - `index` — the entry's row in `index.json`, rebuilt from the file, the
     submission event's position and the seal that covers it;
   - `core` — the core in the file against the core the log actually sealed;
   - `signature` — the author's Ed25519 signature over that core;
6. and then, for a v0.7 entry, the same `verifyOffline` the paper's one script
   runs: schema, chain, author signature, the core against the core the log
   sealed, every record signature, the exclusions replayed at each decision's
   position, every derived field, the snapshot hash, and the inclusion proof;
7. every attestation file, re-derived from the mirror's own events and diffed,
   and then the whole set through `verifyAttestations` — the id over the request,
   each score's signature and signer, the probe and answers hashes, and the fold;
8. `standing.json`, recomputed through `standingAt` at the sealed head;
9. `ledger.jsonl`, recomputed from the sealed events and diffed line by line.

`ok <id>` is a check that held. `FAIL <id> <check> <field> <reason>` is one that
did not, and there is one line per difference. `legacy <id>` is a record sealed
under schema v0.6, before entries carried a `domain`. It is never reported as
`ok`, and it is not waved through either: step 5 runs over it in full, because
those are rules about the log rather than rules v0.7 invented, and a failed
check on a legacy record is a `FAIL` line and exit 1 like any other. What is
left off is step 6 — the captures, the decision records, the v0.7 rules — which
cannot be applied to bytes that never claimed them, and the line says so:

```
legacy <id> (v0.6 record, not decided on again; core, signature, derivation,
chain, and seal checked; captures and records not, the verifier checks v0.7 only)
```

The last line is the summary. The exit code is the answer: **0** when nothing
failed, **1** on any failure or an unreadable directory, **2** on a usage error.

`--entry <id>` checks one entry instead of all of them. The manifest, the chain,
the seals and the anchors are checked either way — they are what the entry rests
on.

### The captures

The mirror holds snapshot **hashes**, never the snapshots. That is Section 11's
design: the captured pages are a third party's bytes, they live outside the
mirror as an evidentiary archive, and a withdrawal removes a copy while the
proof stays exactly where it was. So the verifier fetches them.

- By default it fetches from `mirror.json`'s `captures_base` — the environment's
  own `/captures/` — which is `GET /captures/{hash}` plus its
  `GET /captures/{hash}/sidecar` for the content type the hash was taken under.
- `--captures <url>` points at another origin serving the same shape.
- `--captures <dir>` reads a local archive: one file per capture, **named by the
  hex of its hash** (the `sha256:` prefix dropped), with an optional
  `<hex>.meta.json` beside it holding `{"content_type": "..."}`. A capture with
  no sidecar is read with no content type, which is what the norm rule reads as
  "no header was served".

A capture nobody can produce is a named difference on that one entry, never a
crash — which is exactly what a withdrawn page should look like to a reader.

### Building the mirror yourself

You do not have to believe the published export either. `npm run mirror` builds
the same directory from the public API of any instance, using nothing but the
reads a stranger has:

```sh
npm run mirror -- https://app.nomankind.ai ./my-mirror
diff -r ./my-mirror/production ../log/production
```

Both paths hand the same input to the same builder, so for the same sealed head
the bytes are the same and `diff` is silent. If it is not, one of the two is
wrong and you have the evidence in your hands. The sealed head is pinned from
the seal chain before anything else is read; an instance that seals again
mid-read stops the command with `head_moved` rather than mixing two moments into
one directory.

### One entry, the paper's way

The mirror is the whole log. For a single entry from a live instance, the
paper's two files and one script still work:

```sh
npm run export -- https://app.nomankind.ai <entry-id> ./out
npm run verify -- ./out/entry.json ./out/log.json
```

## Keeping going without nomankind

If nomankind stops, nothing you hold stops working. The clone verifies offline,
forever, with no server anywhere.

To run your own instance, deploy this code to your own Cloudflare account with
your own keys, exactly as the README describes: your own D1 database and R2
bucket from `wrangler.jsonc`, the migrations under `migrations/` applied in name
order, and your own `SEALING_AGENT_KEY`, `MAINTAINER_AGENT_ID` and — if you want
your own daily export — your own mirror repository and a credential that can
write to it. Your operators register against your instance, your sweep seals and
anchors, and your mirror is your archive.

The credential is a GitHub App, and it is a GitHub App rather than a token
because it does not expire: an export that stops because nobody renewed a secret
is an outage with nothing wrong behind it, on a date nobody wrote down. Create a
GitHub App under your account or organisation, give it **Contents: read and
write** on the log repository and no other permission, install it on that
repository alone, generate a private key, and set two Worker secrets:

```sh
npx wrangler secret put MIRROR_APP_ID          # the App's id, from its settings page
npx wrangler secret put MIRROR_APP_PRIVATE_KEY # the .pem GitHub downloaded once
```

The key is read as GitHub writes it — PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)
or PKCS#8, with its newlines, with them flattened into one line, or with them
spelt `\n` — because a credential that has to be pasted in exactly one shape is
a credential that gets pasted wrong. The Worker signs a short-lived JWT with it
and mints an installation token scoped to that one repository at the start of
each push; the token lives for the push and no longer.

`MIRROR_TOKEN`, a personal access token with push access to the same repository,
is the fallback, and is read only when the two App secrets are not both set. To
move from one to the other: set the App secrets, watch one export land, then
delete the token. Neither credential is ever logged, returned, or put in a
refusal's detail — a mirror that named its own token in an error message would
publish it.

**Replaying a mirror into a fresh database is not part of this milestone, and we
would rather say so than imply it.** The export is complete — every event, every
seal, every anchor and every derived entry are in it — but the importer that
loads one into a new instance's D1 does not exist yet. What you can do today is
verify a mirror end to end, keep it, serve it as files, and start a new log of
your own with this code. What you cannot do today is press a button and resume
nomankind's log inside your own Worker.

## The legal posture

- **The log is CC0-1.0.** The entries, events, hashes, seals, anchors and
  indexes in the mirror are dedicated to the public domain. Fork it, mirror it,
  train on it, sell what you build from it. No attribution is required and none
  is asked for.
- **The code is Apache-2.0**, in this repository, patent grant included.
- **The snapshots are not in the mirror.** Only their hashes are. The captured
  bytes are served from the archive at `/captures/{hash}`, and they are somebody
  else's copyrighted page held as evidence of what it said at a moment. A legal
  takedown can remove that served copy; it cannot remove the hash, the
  signatures, the seal or the inclusion proof, and an entry whose capture has
  been withdrawn still verifies as everything but its snapshot. That asymmetry
  is the point of hashing the page instead of republishing it.
- **Exit is a protocol right, not a favour.** Nothing in the mirror is licensed
  in a way that lets it be taken back, and nothing about verifying it requires
  our permission, our uptime or our consent.
