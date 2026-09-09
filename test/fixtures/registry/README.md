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

Registry public key (Ed25519, base64url): mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw
