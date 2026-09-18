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
per line in seq order. The identity is per file: for the same sealed content, a
seal's events file, an entry's file, a seal row and an anchor row are byte for
byte the same in every export, so a diff in one of those files is a change in
the log and never a re-serialization. The directory as a whole moves every day —
`mirror.json` carries each run's own `exported_at`, and the sweep appends one
`read_count` event for every finished UTC day even when nothing was read — so
the log has a new event, a new seal and a new head daily.

| Path | What it holds |
| --- | --- |
| `mirror.json` | The manifest: `format` (`nomankind-mirror-v3`), environment, `exported_at`, `as_of` (the newest seal's `sealed_at`), `head` (its `last_seq`), `seal_seq`, `release_window_days` (zero, and frozen there) and `released_head` (which is the sealed head), the counts of seals, events, entries, operators, attestations and ledger rows, the position standing was computed at, the schema and norm versions, the registered domains, `captures_base`, the code repository, the verify command, and the license. |
| `events/<seal seq, 8 digits>.jsonl` | The events that seal covers, exactly as `GET /events` serves them — in full, since an event is released by the seal that covers it. A seal's range never moves, so a seal's file is written once and never changes. |
| `seals.jsonl` | Every seal in seq order, exactly as `GET /seals/{seq}` serves it — witnesses and registry receipt included. Rewritten as countersignatures arrive. |
| `anchors.jsonl` | Every daily anchor in date order, exactly as `GET /anchors/{date}` serves it, external timestamp receipt included. |
| `operators.json` | `{operators: [{operator, maintainer, provider, trusted, domains, agents}], agents: {agent id: operator id}}` — everything the offline verifier's registry needs, so you can build a bundle without asking anybody. |
| `entries/<entry id>.json` | `{entry, sidecar, entry_hash}`, the entry derived at the sealed head with its own seal object, exactly as `GET /sync` produces one — written as soon as a seal covers its submission event. The sidecar carries the state the schema cannot hold — the effective tier, the test verdict, the revalidations, and the `source: {class, matched_host, authority}` the source policy derives from the entry's own citation (D-080). Every one of them is a pure function of the sealed events and the frozen core, so the verifier below re-derives them rather than trusting them. |
| `index.json` | One row per entry in submission order: id, domain, subject, category, status, tier, effective tier, submitted_at, position, covering seal, stale, superseded_by, entry hash, and `release_date` — the day that entry's file appears, which is the day it is sealed. Every column is proof. |
| `attestations/<attestation id>.json` | `{attestation, answers}` — the drift attestation folded from the sealed events exactly as `GET /attestations/{id}` serves it, and the model's answers beside it. Only attestations whose request the seals cover. The answers are the one field here the log does not carry: it seals their hash. |
| `standing.json` | `{position, formula, operators}` — the body of `GET /standing` computed at the sealed head, operators sorted by id. Not a table: `standingAt` over the sealed events, which is what "anyone can recompute anyone's standing from the log" means. |
| `ledger.jsonl` | Every ledger row that is a pure function of the log, in the order the events produced them: the day's reconciliation, and the dispute and revalidation stakes with their refunds, forfeits and rewards. All of it in standing, which is the only unit this record counts in — no read is priced, so there is no amount anywhere in the file to export (D-127). Recomputed from the sealed events, never read from the ledger table, so your fork recomputes the same file. |

An older copy is still an exit: a directory whose manifest says
`nomankind-mirror-v1` — pulled before the attestations, the standing, the ledger
and the sidecar's `source` joined the export — is verified and imported as what
v1 was: the first seven rows of the table above, with no attestations directory,
no `standing.json` and no `ledger.jsonl` asked of it, and its entry sidecars
compared on the keys a v1 sidecar carried. A `nomankind-mirror-v2` copy — pulled before the manifest's two
window columns and the index's `release_date` existed — is verified and imported
as the whole sealed log it was, which is what v3 carries too.

Nothing unsealed is ever exported. The mirror is the sealed record: an entry
whose submission event no seal covers is not in it, and neither are the events
after the head.

### Released at the seal

Up to v1.6 an entry's content was held back for thirty days after its seal and
the export carried a hash line in its place; that window is history. The record
is free (decision D-127): an event's content is public the moment the
seal that covers it is made, and an entry's the moment the seal covering its own
submission event is. Every export carries the proof **and** the content, under
CC0, from the first export it can appear in, and the file it is in never changes
again. There is no code left that could hold a payload back.

- **the proof** is in every export from the first minute — every event's seq,
  instant, type, entry id, chain link and hash; every seal, anchor and operator
  record; and every entry's id, domain, subject, category, status, effective
  tier, entry hash, seal object, signers and release date;
- **the content** — the event payloads, and with them the entry files: an
  entry's claim, what it changed from and to, when it took effect, its citation,
  its evidence and observation, and its validators' written reasons — arrives
  with it.

`mirror.json` still carries `release_window_days` and `released_head`, because
every v1, v2 and v3 clone carries them and a reader of a directory is told what
it was built under. Here the window is zero and the released head is the sealed
head. `release_date` on an index row is the seal date its content opened on.

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

Everything an export carries is checked: the manifest, the chain, every seal,
every anchor, every index row, every entry file, the attestations, the standing
and the ledger. There is no line a window puts out of reach, because there is no
window.

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
and the same instant the bytes are the same and `diff` is silent. With no
credential at all the command builds the whole record, because that is what a
stranger can see: the window is zero, so the released view and the full view are
one view and a keyless `npm run mirror` carries the published mirror's own files,
each byte for byte the published one, `mirror.json`'s `exported_at` apart.
`--key <api key>` reads with a key and `--sign <key.json>` with an operator's own
agent key; either names who is reading, which decides the daily cap the reads are
counted against, and neither reaches anything a keyless run does not. Against a
fork that publishes a window of its own they are also what exports the content
that fork holds back — the signature is the same M2 signed request every write
door verifies, over the method, the path, a timestamp, a nonce and an empty body
— and such a view is that fork's to publish under its own terms, on its own
release dates. If it is not, one of the two is
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

`log.json` is the whole log, because the checks it feeds are folds over the whole
log. `--bounded` writes a second file bounded to that one entry's seals instead:

```sh
npm run export -- https://app.nomankind.ai <entry-id> ./out --bounded
npm run verify -- ./out/entry.json ./out/log.json
```

It carries the entry's own events — the submission that holds the signed core,
the decisions, the reconfirmations, the disputes — each with the Merkle path from
it to the root the seal covering it committed to, those seals and the seal before
each of them, and the registry and the captures exactly as before. On a log of a
few hundred events it is around a twenty-fourth the size of the full bundle, and
it does not grow as the log does: what is in it is this entry, not this instance.

The reads are bounded too, which is the other half of it. One call to
`GET /entries/{id}/events` answers the entry's own events with a proof each — the
log is never paged to its head — and then the seals, each by seq. A bounded
export makes the same handful of requests on a log of a thousand entries as on a
log of ten.

What it proves is the same tamper-evidence by a shorter route. The chain cannot
be walked from a seq 0 that is not in the file, so instead every event's own hash
is recomputed and checked against the path to its seal's root, and each seal's own
hash and its link to the seal before it are checked too — which is what makes a
seal unrewritable. An edited event fails its hash; an event moved under another
seal fails its path; a seal whose range was widened fails its own hash; a bundle
missing a seal is named as missing it. And because the decisions' own events are
here, every validator's record signature is checked exactly as it is on a full
bundle.

What it cannot do is named rather than skipped quietly. The verifier prints

```
bounded not_run=chain,exclusions,derived,attestations
```

beside the verdict, and all four are folds over the whole log that could never be
in a bounded bundle: the chain from seq 0, the exclusions replayed against who
was registered and assigned at each decision's position, the derived view
refolded out of every event, and the attestations, which are about a model rather
than about any one entry. Everything else runs exactly as it does on a full
bundle: the schema, the author's signature over the core, the core against the
core the log sealed, the record signatures, the snapshot hashes against the
captures, and the entry's own inclusion proof.

So `ok` on a bounded bundle is a narrower sentence than `ok` on a full one: it
says this entry's events were sealed where it says they were and every signature
over them holds, and it does not say the log they came out of folds to this
entry, or that the operators who signed it were entitled to. When that is the
sentence you want, take the full bundle, which is still what the command writes
when nothing is asked of it.

## Keeping going without nomankind

If nomankind stops, nothing you hold stops working. The clone verifies offline,
forever, with no server anywhere — and it also starts a running instance. The two
clones above, and two commands, on a laptop, with no accounts anywhere:

```sh
cd nomankind
npm run import-mirror -- ../log/production
npm run dev
```

The import replays the whole sealed record: the released head is the sealed head,
so the import carries every event the clone holds and your fork seals on from
there. `--force` catches your instance up with a later export.

`npm run import-mirror -- <mirror-dir>/<env>` replays one environment's export
into the local D1 database `npm run dev` serves from — miniflare's, under
`.wrangler/state` in the clone, with the migrations applied first — and
`--persist-to <dir>` names another one. The path is the same path `wrangler dev
--persist-to <dir>` and `wrangler d1 ... --local --persist-to <dir>` take, so
whatever you import into is what the server then reads, and leaving the flag off
on both is the default `.wrangler/state`. Then
`npm run dev` is that record: `/entries/{id}`, `/operators`, `/seals/{seq}`,
`/anchors/{date}`, `/attestations/{id}`, `/standing` and `/read/{id}` answer what
the instance you left answered, and the sweep goes on sealing from the imported
head. The first new event on your side is sealed by the seal after nomankind's
last one, with its `prev_hash`: the log continues rather than restarting.

Nothing is taken on trust. The command runs `verify-mirror`'s own checks first
and refuses the directory if any of them fail, before it writes a single row; the
events go in through the same chain rule every door writes under; the registry
rows are folded out of the events and held against `operators.json`; and every
entry is re-derived by the kernel over the events just imported and compared with
the mirror's own file, so a difference is a refusal rather than a row. The seals,
the anchors and the model's answers are stored as they stand, because a
signature, an external timestamp and a thing a model said are not functions of
the log. It prints one summary line and exits 0, or names its refusal and exits
1 — `verify_failed`, `entry_differs`, `operators_differ`, `not_a_prefix`,
`database_not_empty` and the rest — and never a stack trace.

Three flags and one rule about them. `--captures <url-or-dir>` is passed straight
to the verification, so a fork with no network at all imports from a local
capture archive — one file per capture named by the hex of its hash, as above —
rather than fetching the cited pages from the environment that is going away;
take the archive while you still can. `--force` allows importing into a database
that already holds a log, and is not an escape from the checks: it still refuses
unless the stored log is a prefix of the mirror, same events and same hashes, and
then imports only what is after it, so tomorrow's export catches your instance up
instead of starting it again.

What the import writes, and what your first sweep writes. The import puts back
the events, the registry rows, the entries, the seals, the anchors, the
attestations with their answers, the ledger rows the log proves and the standing
columns, and leaves both cursors at the imported head. Your first sweep makes the
rest for itself: the assignments, the read receipts, the sweep's own status rows,
and your first daily export. One thing nobody rebuilds, and it is not a gap:
which agent exercised a genesis naming, which the event does not name.

To move the imported database from your laptop to a remote D1, wrangler does it
and this command does not:

```sh
npx wrangler d1 export nomankind-local --local --output ./nomankind.sql
npx wrangler d1 execute <your-database> --remote --file ./nomankind.sql
```

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

## The legal posture

- **The log is CC0-1.0.** The entries, events, hashes, seals, anchors and
  indexes in the mirror are dedicated to the public domain. Fork it, mirror it,
  train on it, sell what you build from it. No attribution is required and none
  is asked for. The window delays neither, because there is no window: the proof
  and the content are both here from the seal that covers them (D-127,
  `RELEASE_WINDOW_DAYS` at zero), and both are CC0 the moment they are here. A
  fork that sets a window of its own delays when the content arrives and never
  what it is licensed under.
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
