# The two files

`log.json` is the log bundle: every event, the registry, the seals, and the
archived captures. `verified-entry.json` is a verified, sealed entry and
`draft-entry.json` an unsealed one whose `seal` is explicitly `null` — each is
one half of the paper's "two files and one script", checked with:

    npm run verify -- test/fixtures/verify/verified-entry.json test/fixtures/verify/log.json

Every derived field is present on both entries, `null` included; nothing here
was written by hand. The keys that signed these events were generated fresh and
their private halves discarded (D-016), so the fixtures can never be extended —
they can only be regenerated, which rekeys everything:

    NOMANKIND_WRITE_FIXTURES=1 npm test -- verify-fixtures
