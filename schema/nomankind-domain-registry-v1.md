# nomankind domain registry, v1

The log's mechanism does not care about the domain (whitepaper Section 3, "The
log"). A fact is a claim, a citation, a snapshot hash and a set of signatures,
and none of those five words says "AI". What is domain-shaped is not the
mechanism but the *tables*: which categories exist, how long a fact of each
category stays fresh, which categories carry a transcript, who is too close to
judge, and how a subject is named. This document is where those tables are
published, one block per domain.

Every entry names its domain in the signed core (`domain`, the eighteenth key,
schema v0.7). The field is covered by the entry id, the entry hash and the
author's signature, so an entry can never be re-homed: a fact filed in one
domain cannot be moved into another by anyone, including nomankind.

`src/policy.ts` carries exactly these tables as `DOMAINS`, keyed by slug, and
nothing category-shaped is global any more. The schema's `category` enum is the
union of every registered domain's categories; which categories a domain
actually admits is enforced from this registry by the application, because JSON
Schema cannot express a per-domain enum without splitting the schema.

Three domains are registered (decision D-096, 2026-09-11): `ai-ecosystem`,
`ai-governance` and `ai-safety`. One fact has one home, and the author rule that
decides which is short. An instrument issued by a state or an intergovernmental
body belongs to governance, whatever its force. What a non-state party committed
to about harm to people, and what its systems and its guardrail products do,
belongs to safety. What models cost and do stays in the ecosystem.

## The exclusion rule, in its neutral form

Whitepaper Section 10, "Governance and legal posture", states the rule for the
AI ecosystem: no lab or model provider may be a maintainer, funder, or trusted
operator. The rule is not about labs. It is about distance, and it reads the
same in every domain:

> No party whose products or conduct the record checks may control, fund, or
> validate it in that domain.

So each domain names its own excluded parties, and each domain has its own
independence attestation: one fixed sentence, signed verbatim, so what an
operator put its key to is the same string every reader can recheck years
later. Registration binds an operator to its first domain's attestation. An
operator that wants to work in a second domain signs that domain's attestation
and joins, and the join is a public event in the log. Exclusion is therefore
per domain and never global: a party excluded in one domain stays eligible in
another, which is the whole reason the attestation is a sentence about a
relationship rather than a badge.

## Registered domains

### ai-ecosystem

**Name.** The AI ecosystem.

**Categories.** `release`, `deprecation`, `pricing`, `limit`, `behavior`,
`outage`, `misbehavior`, `correction`.

**Staleness window per category**, in days from the last-confirmed date; `null`
means the category carries no window, because once the thing happened it stays
having happened (whitepaper Section 5, "Freshness and decay"):

| category | window |
| --- | --- |
| release | null |
| deprecation | null |
| pricing | 90 |
| limit | 90 |
| behavior | 30 |
| outage | null |
| misbehavior | null |
| correction | null |

**Transcript categories.** `behavior` and `misbehavior`. These are always
observed and always carry a frozen transcript artifact in `evidence`; every
other category carries its measurement in `observation` instead.

**Excluded parties.** Model providers, by registrable domain and by any
subdomain of one. The rule: no lab or model provider may be a maintainer,
funder, or trusted operator of the AI-ecosystem record. The published list:

openai.com, anthropic.com, google.com, deepmind.google, meta.com,
microsoft.com, x.ai, mistral.ai, cohere.com, amazon.com, deepseek.com,
alibaba.com, alibabacloud.com, moonshot.cn, 01.ai, ai21.com, nvidia.com,
ibm.com, baidu.com, tencent.com, bytedance.com, zhipuai.cn

The list is the maintainer's published policy, not a whitepaper list, and it
moves only by a later decision. It is the cheap first check and never the whole
enforcement: the signed attestation below and the public record behind it are
what actually bind.

**Independence attestation.** Version `nomankind-independence-v1`. The sentence,
signed verbatim:

> No model provider holds control of, or a beneficial stake in, this operator.

**Subject naming convention.** `<provider>/<model or product>`, lowercase, as
the schema's `subject` description gives it: for example `openai/gpt-5`.

**Sources.** Who may be cited for what (decision D-080, 2026-09-10). A stated
entry is verified when independent operators confirm the source said what the
entry says (whitepaper Section 4; Section 12, "stated entries are about the
source, not the world"). Nothing in that sentence asks whether the source is one
that should be believed about that subject, so a site made yesterday could carry
a pricing claim to verified. This table is the answer. Every entry carries a
source class derived from its own citation; some categories are gated on it, and
everywhere else it is a label published beside the entry.

*The three classes.*

| class | what it means |
| --- | --- |
| official | the host is one the subject's own authority published, from the authorities table below |
| recognized | the host is on the recognized list below: an editorial process, a standards body, a court or regulator, a journal or a preprint server |
| other | neither. Not an accusation: it says this log publishes no authority for this subject |

*The host rule.* The citation must be `https`; `http` is `other` and never
official or recognized, because a plaintext fetch is a source anybody on the path
can rewrite. The citation's host, lowercased, matches a listed host exactly or as
a subdomain of it — `docs.anthropic.com` matches `anthropic.com`, and
`anthropic.com.evil.tld` does not. A port or userinfo in the citation makes it
`other`. Where several listed hosts match, the longest is the one published.

*Official-required categories.* `pricing`, `limit`, `deprecation`, `release`,
`outage`. These have an authoritative source by nature — what a product costs,
what its limits are, what was released, deprecated, or down is the authority's
own to state — so an entry in one of them must cite the subject's official
source or it is refused at submit, with `unknown_authority` when the subject's
primary party has no row and `source_not_official` when it has one and the
citation is not among its hosts. A correction entry is a submission like any
other, and is checked under its own category — `correction`, which is not
official-required — so the rule that binds a challenge is the one its target
carries: the dispute door runs the same check against the challenged entry's
domain and category, and overturning an official-required claim takes an
official source too.

*The authorities table.* The subject convention is `<provider>/<model or
product>`, so the subject's primary party — the first path segment, lowercase —
keys this table. Every excluded party of this domain appears here: a party too
close to judge the record is exactly the party whose own pages are authoritative
about its own products. An authority absent from the table has no official
source published here, so its official-required claims are refused until a
decision adds the row.

| authority | official hosts |
| --- | --- |
| openai | openai.com, platform.openai.com, status.openai.com, help.openai.com |
| anthropic | anthropic.com, docs.anthropic.com, status.anthropic.com, claude.com, docs.claude.com |
| google | google.com, ai.google.dev, cloud.google.com, status.cloud.google.com, deepmind.google, blog.google |
| meta | meta.com, ai.meta.com, llama.com |
| microsoft | microsoft.com, azure.microsoft.com, learn.microsoft.com |
| xai | x.ai, docs.x.ai, status.x.ai |
| mistral | mistral.ai, docs.mistral.ai, status.mistral.ai |
| cohere | cohere.com, docs.cohere.com, status.cohere.com |
| amazon | amazon.com, aws.amazon.com, docs.aws.amazon.com, health.aws.amazon.com |
| deepseek | deepseek.com, api-docs.deepseek.com, status.deepseek.com |
| alibaba | alibaba.com, alibabacloud.com, help.aliyun.com |
| moonshot | moonshot.cn, platform.moonshot.cn |
| 01-ai | 01.ai |
| ai21 | ai21.com, docs.ai21.com |
| nvidia | nvidia.com, docs.nvidia.com, build.nvidia.com |
| ibm | ibm.com, cloud.ibm.com |
| baidu | baidu.com, cloud.baidu.com |
| tencent | tencent.com, cloud.tencent.com |
| bytedance | bytedance.com, volcengine.com |
| zhipuai | zhipuai.cn, open.bigmodel.cn |
| example | example.com, example — a fixture, never a real subject |

`example` is the reserved-name row (RFC 2606): `example.com`, which the demo's
own checkpoint cites, and the `example` top-level domain itself, which every
`*.example` fixture host is a subdomain of. Both are reserved by IANA and can
never be registered, so nothing in this row can become a real authority's
official host. It is marked a fixture in `DOMAINS`, and the test that pins this
table against the excluded-party list skips it for that reason.

*The recognized list.* A label and never a gate; it grows by decision:

arxiv.org, doi.org, openreview.net, acm.org, ieee.org, nature.com, science.org,
nist.gov, iso.org, ietf.org, w3.org, sec.gov, federalregister.gov,
courtlistener.com, gov.uk, europa.eu, eur-lex.europa.eu, reuters.com,
apnews.com, bloomberg.com, nytimes.com, wsj.com, ft.com, theverge.com,
techcrunch.com, wired.com, arstechnica.com

*What the policy does not automate.* A validator's approval asserts that the
cited page supports the claim. This table says only which pages may be cited at
all; whether the page says what the entry says it says is the judgment the
validators make, and no host list can make it for them.

Both lists are the maintainer's published policy, not whitepaper lists, and both
move only by a later decision.

### ai-governance

**Name.** AI governance.

**Categories.** `in_force`, `amended`, `repealed`, `guidance_issued`,
`enforcement_action`.

**Staleness window per category**, in days from the last-confirmed date; `null`
means the category carries no window, because once the thing happened it stays
having happened. An instrument in force keeps being in force until something
changes it, but what is in force is worth re-reading on a cadence, and a year is
that cadence:

| category | window |
| --- | --- |
| in_force | 365 |
| amended | null |
| repealed | null |
| guidance_issued | 365 |
| enforcement_action | null |

Both windows are the maintainer's own placeholders, not whitepaper numbers, and
move only by a later decision.

**Transcript categories.** None. Every category here rests on a document
somebody published, so every entry carries its measurement in `observation` or
nothing at all; nothing in this domain is measured against a model.

**Excluded parties.** Two kinds of party, excluded two different ways. The model
providers are ai-ecosystem's published list above, unchanged and by any
subdomain of one: a provider is as close to a rule about it as to a price of it.
The issuing bodies are excluded per entry rather than by list, because the body
that issued the instrument is named by the entry's own subject — an operator
whose domain is, or is under, an official host of the subject's authority row
may not validate that entry, reconfirm it, or be drawn for it. The rule:

> No body that issues an instrument this domain records, and no model provider,
> may be a maintainer, funder, or trusted operator of the AI-governance record.

**Independence attestation.** Version `nomankind-independence-v1`. The sentence,
signed verbatim:

> No model provider, and no body that issues an instrument this record checks,
> holds control of, or a beneficial stake in, this operator.

**Subject naming convention.** `<jurisdiction or body>/<instrument slug>`,
lowercase: for example `eu/ai-act`, `us/eo-14110`, `iso/42001`. The authority is
the first segment.

**Sources.** The three classes, the host rule, and what the policy does not
automate are ai-ecosystem's above, unchanged: they are properties of a citation
and not of a domain. What this domain publishes is its own three tables.

*Official-required categories.* `in_force`, `amended`, `repealed`,
`guidance_issued`. What an instrument says, when it took force, when it was
amended or repealed, and what guidance was issued under it are the issuing
body's own to state. `enforcement_action` is not official-required: an
enforcement is recorded by a court or a regulator, which the recognized list
covers.

*The authorities table.* The subject convention is `<jurisdiction or
body>/<instrument slug>`, so the first segment keys this table. Every host below
was fetched once and confirmed to answer. The table is the maintainer's own
placeholder list and grows only by a later decision.

| authority | official hosts |
| --- | --- |
| eu | europa.eu, eur-lex.europa.eu, digital-strategy.ec.europa.eu |
| coe | coe.int |
| us | federalregister.gov, whitehouse.gov, congress.gov, govinfo.gov, regulations.gov |
| us-ca | ca.gov, leginfo.legislature.ca.gov |
| us-co | colorado.gov, leg.colorado.gov |
| us-ny | ny.gov, nysenate.gov |
| uk | gov.uk, legislation.gov.uk |
| iso | iso.org |
| nist | nist.gov |
| oecd | oecd.org, oecd.ai |
| unesco | unesco.org |
| un | un.org |
| example | example.com, example — a fixture, never a real subject |

*The recognized list.* ai-ecosystem's recognized list above, plus the courts and
data-protection bodies that record what was enforced under an instrument:

curia.europa.eu, supremecourt.gov, edpb.europa.eu

### ai-safety

**Name.** AI safety.

**Categories.** `commitment_published`, `commitment_changed`,
`commitment_withdrawn`, `conduct_observed`, `refusal_behavior`,
`filter_behavior`, `safety_eval`, `incident`.

**Staleness window per category**, in days from the last-confirmed date; `null`
means the category carries no window. What a system does is as volatile as
ai-ecosystem's `behavior`; an evaluation is a heavier measurement that moves
more slowly, so it carries a quarter rather than a month:

| category | window |
| --- | --- |
| commitment_published | null |
| commitment_changed | null |
| commitment_withdrawn | null |
| conduct_observed | 30 |
| refusal_behavior | 30 |
| filter_behavior | 30 |
| safety_eval | 90 |
| incident | null |

The four windows are the maintainer's own placeholders, not whitepaper numbers,
and move only by a later decision.

**Transcript categories.** `conduct_observed`, `refusal_behavior` and
`filter_behavior`. These are always observed and always carry a frozen
transcript artifact in `evidence`, exactly as behavior and misbehavior are in
ai-ecosystem. `safety_eval` carries its measurement in `observation`;
`incident` and the three commitment categories are stated.

**Excluded parties.** Model providers and guardrail vendors, by registrable
domain and by any subdomain of one. A product that decides what a model refuses
is a product this domain's entries are about, so its vendor is as close to the
record as a provider is. The published list is ai-ecosystem's twenty-two model
providers above, plus:

lakera.ai, protectai.com, hiddenlayer.com, calypsoai.com, arthur.ai,
guardrailsai.com, patronus.ai, promptfoo.dev

The party named by an entry's own subject is excluded from that entry as well:
an operator whose domain is, or is under, an official host of the subject's
authority row may not validate that entry, reconfirm it, or be drawn for it. The
rule:

> No model provider, no guardrail vendor, and no party funded by one may be a
> maintainer, funder, or trusted operator of the AI-safety record.

The vendor list is the maintainer's published policy, not a whitepaper list, and
it moves only by a later decision.

**Independence attestation.** Version `nomankind-independence-v1`. The sentence,
signed verbatim:

> No model provider, no guardrail vendor, and no party funded by one, holds
> control of, or a beneficial stake in, this operator.

**Subject naming convention.**
`<party>/<document or model>, or <party>/<model>/<version>`, lowercase. The
first form names the commitment and
incident categories, for example `anthropic/usage-policy`; the second names the
version-staleness categories below, for example `openai/gpt-5/2026-08`, because
an observation is about the version it was made against. The authority is the
first segment either way.

**Sources.** The three classes, the host rule, and what the policy does not
automate are ai-ecosystem's above, unchanged.

*Official-required categories.* `commitment_published`, `commitment_changed`,
`commitment_withdrawn`. What a party committed to, changed, or withdrew is that
party's own to state. Conduct, a refusal, a filter, an evaluation and an
incident are not: they are what somebody else found.

*The authorities table.* Every ai-ecosystem authority row above, unchanged — a
provider's own pages are authoritative about the provider's own commitments —
including the `example` fixture row, plus the rows below. Every host below was
fetched once and confirmed to answer; the added rows are the maintainer's own
placeholders and grow only by a later decision.

| authority | official hosts |
| --- | --- |
| lakera | lakera.ai |
| protectai | protectai.com |
| hiddenlayer | hiddenlayer.com |
| calypsoai | calypsoai.com |
| arthur | arthur.ai |
| guardrailsai | guardrailsai.com |
| patronus | patronus.ai |
| promptfoo | promptfoo.dev |
| pai | partnershiponai.org |
| fli | futureoflife.org |
| fmf | frontiermodelforum.org |
| mlcommons | mlcommons.org |

*The recognized list.* ai-ecosystem's recognized list above, plus the public
register of AI incidents:

incidentdatabase.ai

#### Delayed disclosure

A transcript in this domain is often evidence whose sensitive half is the
request that produced it. So inside a transcript artifact's `request`, any value
but `headers` may be submitted as the placeholder object `{"[REDACTED]":
"sha256:<hex>"}`, where the hex is the SHA-256 of the RFC 8785 canonical JSON of
the original value. The categories that may do it are `conduct_observed`,
`refusal_behavior` and `filter_behavior` — this domain's transcript categories,
and nothing else — and anywhere else a redacted load-bearing value is refused
exactly as it is today.

The submission carries the original values beside the artifact, keyed by JSON
pointer, and they are archived at their own content address like every other
capture. The transcript hash is taken over the artifact as submitted,
placeholders included, so the author's signed `snapshot_hash` verifies against
the archived artifact unchanged and the offline verifier never asks for the
payload at all.

The payload is public 90 days after the entry's `submitted_at`. Before then
it is served only to an operator's signed request — the validators need it to
reproduce the observation — and an unsigned read is refused with the date it
opens. Ninety days is the maintainer's own placeholder: long enough that
publishing the payload is not itself the harm, short enough that the evidence
becomes public while the fact is still fresh. It moves only by a later decision.

#### Staleness on a version change

An observation in this domain is about the version it was made against, which is
why `conduct_observed`, `refusal_behavior`, `filter_behavior` and `safety_eval`
name their subject `<party>/<model>/<version>`. A fact about `openai/gpt-5` in
August is not a fact about `openai/gpt-5` in December, and no calendar window
says so on its own.

So an entry in one of those four categories goes stale from the position of the
validation that verifies another entry of the same domain, in one of those
categories, submitted at a later position than this one, and whose subject
shares the party and model segments while differing in the version segment. A
sibling submitted before it never stales it, whenever that sibling verifies, and
neither does one that names the same version. `expires_at` is unchanged: this is a fact about the world
having moved, not about the clock. And a version-stale entry stays stale — a
reconfirmation cannot clear it, because the version it observed is gone.

## Duplicate claims

The same fact filed twice is worth nothing twice, and the rule that says so is
the same in every domain, so it is written here once rather than per domain.

A duplicate is a claim with the same **domain, subject, category and normalized
value** as one already in the log — the value being the entry's `after` put
through the norm-v1.2 text normalization, so the same number written with a
different amount of whitespace is the same value. Nothing else in the core is
part of the key: two entries with the same value at a different `effective_at`
are not duplicates by this rule.

The rule reads against the **live** statuses only, `draft` and `verified`. A
`rejected`, `superseded` or `overturned` entry is not live, and a fact may
always be refiled after any of those — that is how the log corrects itself.

The exception is **supersession**. An entry naming the live one in its own
`supersedes` is the sanctioned way to refile a fact, so it is accepted: the
target's `superseded_by` is written when the superseder verifies, and exactly
one of the two is live at the end.

So the log refuses the mechanical case and leaves the judgment to validators.
A submission whose key matches a live entry it does not supersede is refused at
the door with 422 `duplicate_claim`, naming the existing entry in `duplicate_of`,
before the citation is fetched and before anything is written. Everything the
key cannot decide — two entries saying the same thing in different words, or at
a different `effective_at` — is a validator's judgment, and a validator making
it rejects in a published form: the reason `duplicate_claim:<entry id>`, naming
the verified entry the one under judgment duplicates. Nothing new is signed; the
reason is the schema's own `approvers[].reason` string, and readers parse the id
back out of it.

And a duplicate is not paid. A verified entry delivered in a paid sync counts as
a read only when it is the newest live verified entry of its duplicate group at
the moment the day is published, so two verified entries that are the same fact
earn one entry's read between them and not two.

## Adding a domain

A new domain is a decision, not a pull request: the block above is filled in
first — categories, windows, transcript categories, excluded parties and their
list, attestation version and sentence, subject convention, and the sources
section (the official-required categories, the authorities table with a row for
every excluded party, and the recognized list) — the slug is added to the
schema's `domain` enum, and `DOMAINS` in `src/policy.ts` is extended to match. A
test pins that `DOMAINS`' key set is exactly the schema's enum, so the two can
never drift. Existing entries are untouched: their domain is in their signed
core, and no migration can move them.
