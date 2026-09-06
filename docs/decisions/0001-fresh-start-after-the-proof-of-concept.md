# 0001. Fresh start after the proof of concept

Date: 2026-09-06. Status: accepted.

## Decision

The application is built from scratch in this repository, against the spec (`paper/`, `schema/`), for the web app at `demo.nomankind.ai` (staging) and `app.nomankind.ai` (production) on Cloudflare Workers. The proof of concept built in September 2026 (fourteen milestones plus a storage port, 178 tests, tag `v0.1-poc`) is retired. Its code does not enter this repository; its repository was deleted; a local archive is kept by the maintainer for reference only. What it taught is kept in `docs/POC-RETROSPECTIVE.md`.

`nomankind-ai/nomankind` is the single repository for spec and application. `nomankind-ai/log` stays separate as the CC0 data mirror. `nomankind-ai/.github` holds the organization profile.

## Reason

The PoC proved the mechanics but was shaped by its constraints: a command line as the only write path, file-first storage with an in-memory bridge for Workers, no authentication, stubs for DNS, source fetching, witnesses, and the randomness beacon, and no user interface. Carrying that shape into the application would mean untangling storage from every rule module. Rebuilding from the spec, with the retrospective's rules and the bugs it found already known, is faster and leaves one clean history.

The PoC also carried its own copies of the whitepaper and the schema, and those had begun to drift from the spec. One repository, one copy of each, ends that.

## Alternatives passed over

- Merge the PoC's history into this repository and extract its kernel modules into a package. Rejected: the pure parts were entangled with the file-first store; the extraction would have cost about as much as a rewrite and left a two-headed history.
- Keep a separate code repository. Rejected: the schema is the contract between paper and code and must exist once.

## Consequences

- `docs/PLAN.md`, the PoC milestone plan, is removed; the rebuild's plan is the set of issues labeled `roadmap` and the milestone issues under them.
- Tracking moves from Microsoft To Do to GitHub issues in this repository.
- The rules the PoC settled on are carried forward as working conventions in `CONTRIBUTING.md`: policy numbers in one module, derived fields never set directly, time injected, field names from the schema exactly.
