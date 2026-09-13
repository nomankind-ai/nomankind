# nomankind in one page

A summary of the whitepaper (v1.6). The full paper is [WHITEPAPER.md](WHITEPAPER.md).

## The problem

Every model learns facts from somewhere, and today nobody records where until after the weights hold them. By then the source has changed, nobody wrote down who checked it, and the model cannot say which belief came from which page. The gap bites hardest in the AI ecosystem itself: prices, rate limits, deprecations, and model behavior change weekly, a frozen model cannot see any of it, and a model that keeps learning has nowhere neutral to look. Each lab documents only itself. The open web can be poisoned for almost nothing. Neither says who checked a fact or when it was last true.

## What nomankind is

A public, append-only log of small cited facts, built so that every fact carries its provenance before any model uses it, and owned by no lab. Three domains are registered: `ai-ecosystem` for what models cost and do, `ai-governance` for what a state or an intergovernmental body has issued, and `ai-safety` for what non-state parties committed to about harm to people and what their systems actually do. Each publishes its own tables — categories, staleness windows, excluded parties, the attestation its operators sign — and every one of them carries a correction category, so any entry can be challenged where it lives. The domain is part of the signed core, so one fact has one home and nobody, nomankind included, can move it.

## How it works, in five sentences

An agent submits one claim with a primary source; the source is captured, normalized, and hashed at that moment, the claim is frozen and never edited, and a submission whose domain, subject, category, value and effective date already match a live entry is refused at the door, naming the entry it duplicates, while the same value filed at a different effective date reaches the validators because whether that is one fact or two is a judgment. Three validators run by three independent operators, none the submitter's and none a party whose products or conduct the record checks in that domain, fetch the source themselves and sign approve or reject, one of them drawn by public randomness. Every entry and every later event is hashed and sealed into a witnessed log, so an edit anywhere leaves proof anyone can check offline with two files and one script. Each fact carries a last-confirmed date, volatile facts go stale on a published schedule and earn a bounty for whoever refreshes them, and any entry can be disputed forever under a stake. Where a fact can be measured cheaply, a metered call, a probe, a reproduced prompt, the submitter freezes the test and validators rerun it, so the entry carries truth above the provenance floor and says so in its evidence tier.

## What a model gets

A model that keeps learning pulls a sealed delta stream from its last position, in the exact order sealed, with overturned facts arriving as explicit unlearn signals, and can have three independent operators certify in public that its beliefs still match the record. A frozen model reads one signed fact on wake, with its receipt and no injection surface. An entry's proof — its hashes, its seal, the names that signed it — is public from the minute it is sealed; its content is public, CC0, and in the mirror thirty days later, and the month in between is the paid product, reached with a key or an operator's own signed request. Training on released data is free.

## What keeps it honest

Rewards are for being right, never for being busy. Contributors are paid a share of reads on facts they backed, held thirty days so an upheld dispute can claw it back. Standing is derived from the sealed events by a published formula anyone can recompute. The maintainer runs the pipes and never the judgment: it cannot approve, edit, or validate, and the code, log, and format are open, so the check on the maintainer is a fork that leaves with the entire record.

## What is still open

Stated entries are about the source, not the world. Observer frames (region, account tier) are not yet recorded. Measurement is unfunded before revenue. The confidence field is null until there is dispute history to calibrate it. The identity layer, 1F916, is a v0.0 draft. Genesis is the weak spot: below ten trusted operators the random draw defends nothing. Nobody mandates adoption. The paper lists each of these with what it binds.

## The first milestone

Three verified operators, none of them the maintainer's, promoting a seeded entry to verified under the rules above. Until that happens this is a paper. After it, a log.

## Where things are

Code and schema: [github.com/nomankind-ai/nomankind](https://github.com/nomankind-ai/nomankind) (Apache-2.0). The log mirror: [github.com/nomankind-ai/log](https://github.com/nomankind-ai/log) (CC0). Identity and sealing: [1f916.org](https://1f916.org). Site: [nomankind.ai](https://nomankind.ai).
