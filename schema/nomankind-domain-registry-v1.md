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
