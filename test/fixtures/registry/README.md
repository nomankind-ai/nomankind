# Registry fixtures (captured from the founding 1F916 registry)

Captured on 2026-09-09 03:56 UTC from https://1f916.ai by the orchestrator, verbatim, for the
M16 kernel and adapter tests. They are real wire responses, not hand-made:

- `checkpoint.json`: `GET /api/checkpoint` (heads, the registry public key, the payload formats).
- `proof-identity_events-103.json`: `GET /api/proof?log=identity_events&event=103` (inclusion of
  event 103, leaf index 88, against the checkpoint at tree size 89).
- `consistency-identity_events-89-9128.json`: `GET /api/checkpoint/consistency?log=identity_events&from=89&to=9128`.
- `witnesses.json`: `GET /api/witnesses` (the pointer directory; ids 6, 7, 8 are the D-054 pin).
- `witness-lines-liveness.jsonl`: the last three `identity_events` countersignature lines of the
  liveness witness's published file (witness id 8) at capture time.

Captured on 2026-09-09 21:05 UTC from https://1f916.ai, verbatim, for the seal-event defect (the
seal response's `id` is the registry's seal row, not the identity event that anchors it):

- `record-nomankind.json`: `GET /api/record/nomankind` — nomankind's own citizen record. Its
  `events` array holds the `memory.seal` event that anchors production seal 0: id 9888, hash
  `3eb4ad8a…`, leaf index 9873, detail naming `sha256=a61ae671…`. Its `seals` convenience list
  names the same seal under the registry's seal row id 4281. `events_has_more` is false here; the
  route's own paging parameter, published by `GET /api/surface`, is `?events_since=<last row id>`.
- `proof-identity_events-9888.json`: `GET /api/proof?log=identity_events&event=9888` — the right
  event: hash `3eb4ad8a…`, leaf index 9873, against the checkpoint at tree size 9874.
- `proof-identity_events-4281.json`: `GET /api/proof?log=identity_events&event=4281` — what the
  seal row id asks for and gets: an unrelated August event (hash `38b5f3cb…`, leaf index 4266,
  checkpoint at tree size 4268). Kept so a test can prove it is never accepted as evidence.

Captured on 2026-09-09 21:56 UTC from https://1f916.ai, verbatim, for the bridge-direction defect
(the proof's checkpoint is the *earliest* that covers the event, so a countersigned head is
normally later than it and the bridge runs forward):

- `witness-line-liveness-9971.jsonl`: the newest `identity_events` countersignature line of the
  liveness witness's published file (witness id 8) at capture time — tree size 9971, root
  `a44ac4e2…`, `consistency` "verified from 9963". Later than the head production seal 0's
  inclusion proof was fetched against (9874), which is the whole point of the capture.
- `consistency-identity_events-9874-9971.json`: `GET /api/checkpoint/consistency?log=identity_events&from=9874&to=9971`
  — the forward bridge, from the proof's checkpoint (`9a207489…`) to that countersigned head
  (`a44ac4e2…`). The endpoint requires `0 <= from <= to`, so the reverse question
  (`from=9971&to=9874`) has no answer to capture.

Registry public key (Ed25519, base64url): mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw
