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

## Adding a domain

A new domain is a decision, not a pull request: the block above is filled in
first — categories, windows, transcript categories, excluded parties and their
list, attestation version and sentence, subject convention — the slug is added
to the schema's `domain` enum, and `DOMAINS` in `src/policy.ts` is extended to
match. A test pins that `DOMAINS`' key set is exactly the schema's enum, so the
two can never drift. Existing entries are untouched: their domain is in their
signed core, and no migration can move them.
