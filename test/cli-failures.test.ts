/**
 * How a command leaves the process when something it did not plan for stops it.
 *
 * The QA finding this file closes: `npm run read`, `npm run sync` and
 * `npm run standing`, pointed at a base URL nothing listens on, printed
 * undici's internal frame, a TypeError, and the absolute path of every file on
 * the way down. An operator who mistyped a hostname learned nothing they could
 * act on, and anybody reading over their shoulder learned where the repository
 * lives.
 *
 * So there is one wrapper (src/cli/main.ts) and every entry point goes through
 * it, and this file holds it to three promises: an unreachable base URL is one
 * named line carrying the URL and the platform's own errno; anything else is
 * one named line carrying the command's name; and the stack is not lost, it is
 * behind `NOMANKIND_DEBUG`.
 *
 * Everything is driven in process. The failures are the real ones — a TypeError
 * shaped exactly as Node's fetch throws, with the cause it carries — rather
 * than a socket nobody can rely on being closed on a build machine.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DEBUG_VARIABLE,
  causeOf,
  failureLine,
  isUnreachable,
  runCommand,
  unreachableLine,
} from "../src/cli/main.js";
import type { SnapshotFetcher } from "../src/adapters/fetch.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { runDispute } from "../src/cli/dispute.js";
import { run as runImport } from "../src/cli/import-mirror.js";
import { runRead } from "../src/cli/read.js";
import { runReconfirm } from "../src/cli/reconfirm.js";
import { runRegister } from "../src/cli/register.js";
import { runReport } from "../src/cli/report.js";
import { runRevalidate } from "../src/cli/revalidate.js";
import { runStanding } from "../src/cli/standing.js";
import { runSubmit } from "../src/cli/submit.js";
import { runSync } from "../src/cli/sync.js";
import { verifyMirror } from "../src/cli/verify-mirror.js";
import type {
  HttpClient,
  ValidatorIo,
  ValidatorKey,
} from "../src/cli/validator.js";

const BASE = "https://nothing-listens.example";

/** Exactly what Node's fetch throws when the request never reached anything. */
function fetchFailure(code: string): TypeError {
  const cause = Object.assign(new Error("connect ECONNREFUSED"), { code });
  return Object.assign(new TypeError("fetch failed"), { cause });
}

/** The lines a run printed, kept apart by stream. */
function recorder(): { io: ValidatorIo; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (line) => out.push(line), stderr: (line) => err.push(line) },
    out,
    err,
  };
}

/** A serving side that is not there: every request throws the way fetch does. */
class UnreachableHttp implements HttpClient {
  constructor(private readonly code = "ECONNREFUSED") {}

  async fetch(): Promise<Response> {
    throw fetchFailure(this.code);
  }
}

describe("the named failure line", () => {
  it("recognises a fetch that never reached anything, and nothing else", () => {
    expect(isUnreachable(fetchFailure("ENOTFOUND"))).toBe(true);
    // A TypeError out of this repository's own code is a bug, and reporting it
    // as somebody's network would send them to look at the wrong thing.
    expect(isUnreachable(new TypeError("x is not a function"))).toBe(false);
    expect(isUnreachable(new Error("fetch failed"))).toBe(false);
    expect(isUnreachable("fetch failed")).toBe(false);
  });

  it("carries the platform's own errno rather than undici's sentence", () => {
    expect(causeOf(fetchFailure("ECONNREFUSED"))).toBe("ECONNREFUSED");
    expect(causeOf(fetchFailure("ENOTFOUND"))).toBe("ENOTFOUND");
    // Nothing wrapped: the error's own first line.
    expect(causeOf(new Error("plain\nsecond line"))).toBe("plain");
  });

  it("names the base URL the caller typed", () => {
    expect(unreachableLine(BASE, fetchFailure("ECONNREFUSED"))).toBe(
      `unreachable ${BASE}: ECONNREFUSED`,
    );
    // Null is the signal that this is not that failure, so a caller that
    // catches its own errors keeps printing whatever it printed before.
    expect(unreachableLine(BASE, new Error("something else"))).toBeNull();
  });

  it("names the command for everything else", () => {
    const context = { name: "standing", baseUrl: BASE, io: recorder().io };
    expect(failureLine(context, new Error("the log moved"))).toBe(
      "standing: the log moved",
    );
    // One line, always: a multi-line message is cut at the first.
    expect(failureLine(context, new Error("first\nstack\nframes"))).toBe(
      "standing: first",
    );
  });
});

describe("the entry wrapper", () => {
  it("passes a run's own exit code through untouched", async () => {
    const { io, err } = recorder();
    const code = await runCommand(
      { name: "read", baseUrl: BASE, io },
      async () => 2,
    );
    expect([code, err]).toEqual([2, []]);
  });

  it("turns an unreachable base URL into one line and exit 1", async () => {
    const { io, err } = recorder();
    const code = await runCommand(
      { name: "read", baseUrl: BASE, io },
      async () => {
        throw fetchFailure("ECONNREFUSED");
      },
    );
    expect([code, err]).toEqual([1, [`unreachable ${BASE}: ECONNREFUSED`]]);
  });

  it("turns any other escaped error into one named line and exit 1", async () => {
    const { io, err } = recorder();
    const code = await runCommand(
      { name: "sync", baseUrl: BASE, io },
      async () => {
        throw new Error("nothing sensible happened");
      },
    );
    expect([code, err]).toEqual([1, ["sync: nothing sensible happened"]]);
  });

  it("prints no stack by default and the whole stack on request", async () => {
    const thrown = new Error("with a stack");
    const quiet = recorder();
    await runCommand(
      { name: "sync", baseUrl: BASE, io: quiet.io, debug: false },
      async () => {
        throw thrown;
      },
    );
    expect(quiet.err).toHaveLength(1);
    expect(quiet.err[0]).not.toContain("at ");

    const loud = recorder();
    await runCommand(
      { name: "sync", baseUrl: BASE, io: loud.io, debug: true },
      async () => {
        throw thrown;
      },
    );
    expect(loud.err).toHaveLength(2);
    expect(loud.err[1]).toBe(thrown.stack);
  });

  it("reads the debug switch off the environment when nobody said", async () => {
    const before = process.env[DEBUG_VARIABLE];
    try {
      process.env[DEBUG_VARIABLE] = "1";
      const { io, err } = recorder();
      await runCommand({ name: "sync", baseUrl: BASE, io }, async () => {
        throw new Error("loud");
      });
      expect(err).toHaveLength(2);

      delete process.env[DEBUG_VARIABLE];
      const quiet = recorder();
      await runCommand(
        { name: "sync", baseUrl: BASE, io: quiet.io },
        async () => {
          throw new Error("quiet");
        },
      );
      expect(quiet.err).toHaveLength(1);
    } finally {
      if (before === undefined) delete process.env[DEBUG_VARIABLE];
      else process.env[DEBUG_VARIABLE] = before;
    }
  });
});

describe("the commands that take a base URL", () => {
  /** One key, made for real: nothing here is signed with a placeholder. */
  async function key(): Promise<ValidatorKey> {
    const pair = await generateKeypair();
    return {
      agentId: agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey)),
      privateKey: pair.privateKey,
    };
  }

  /** A citation that answers, so a run reaches the base URL it was pointed at. */
  const fetcher: SnapshotFetcher = {
    fetch: async () => ({
      ok: true,
      bytes: new TextEncoder().encode("<html><body>the source</body></html>"),
      status: 200,
      headers: { "content-type": "text/html" },
      finalUrl: "https://source.example/page",
    }),
  };

  /** The fields file a submission is built from, as the schema wants it. */
  const FIELDS: Record<string, unknown> = {
    subject: "an.example",
    category: "pricing",
    domain: "ai-ecosystem",
    claim: "seat pricing is $40 per seat per month",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01T00:00:00.000Z",
    citation: "https://source.example/page",
  };

  const ENTRY = "nmk_01M25WRITEDOOR";

  // The three the QA of 2026-09-13 found first, and the six write doors the
  // same QA found printing their own last line. Each is driven the way its own
  // entry point drives it, with the network that entry point hands it replaced
  // by one that is not there.
  const cases: readonly {
    name: string;
    run: (http: HttpClient, io: ValidatorIo) => Promise<number>;
    /** Whether the command has something to say before it asks anything. */
    speaksFirst?: boolean;
  }[] = [
    {
      name: "standing",
      run: (http, io) => runStanding([BASE, "an.example"], http, io),
    },
    {
      name: "read",
      run: (http, io) => runRead([BASE, "nmk_0"], http, io),
    },
    { name: "sync", run: (http, io) => runSync([BASE], http, io) },
    {
      name: "submit",
      run: async (http, io) => {
        const run = await runSubmit({
          key: await key(),
          baseUrl: BASE,
          fields: FIELDS,
          deps: { http, fetcher, now: new Date(), io },
        });
        return run.code;
      },
    },
    {
      name: "register",
      // The TXT record the operator must publish is named before anything is
      // asked of anybody, which is the point of naming it.
      speaksFirst: true,
      run: async (http, io) => {
        const run = await runRegister({
          key: await key(),
          baseUrl: BASE,
          domain: "an.example",
          deps: { http, now: new Date(), io },
        });
        return run.ok ? 0 : 1;
      },
    },
    {
      name: "dispute",
      run: async (http, io) => {
        const run = await runDispute({
          key: await key(),
          baseUrl: BASE,
          targetId: ENTRY,
          fields: FIELDS,
          deps: { http, fetcher, now: new Date(), clock: () => new Date(), io },
        });
        return run.ok ? 0 : 1;
      },
    },
    {
      name: "report",
      run: async (http, io) => {
        const run = await runReport({
          key: await key(),
          baseUrl: BASE,
          entryId: ENTRY,
          report: {
            observed: "the page says $45 now",
            artifact: { kind: "note", body: "what the reader saw" },
          },
          deps: { http, now: new Date(), io },
        });
        return run.ok ? 0 : 1;
      },
    },
    {
      name: "revalidate",
      run: async (http, io) => {
        const run = await runRevalidate({
          key: await key(),
          baseUrl: BASE,
          entryId: ENTRY,
          deps: { http, fetcher, now: new Date(), clock: () => new Date(), io },
        });
        return run.ok ? 0 : 1;
      },
    },
    {
      name: "reconfirm",
      run: async (http, io) => {
        const run = await runReconfirm({
          key: await key(),
          baseUrl: BASE,
          entryId: ENTRY,
          deps: { http, fetcher, now: new Date(), clock: () => new Date(), io },
        });
        return run.ok ? 0 : 1;
      },
    },
  ];

  for (const { name, run, speaksFirst } of cases) {
    it(`${name} says the base URL is unreachable rather than throwing`, async () => {
      const { io, err, out } = recorder();
      const code = await runCommand({ name, baseUrl: BASE, io }, () =>
        run(new UnreachableHttp(), io),
      );

      expect([code, err]).toEqual([1, [`unreachable ${BASE}: ECONNREFUSED`]]);
      // Nothing was answered, so nothing is printed as if it had been.
      if (speaksFirst !== true) expect(out).toEqual([]);
    });

    it(`${name} names a hostname that does not resolve the same way`, async () => {
      const { io, err } = recorder();
      const code = await runCommand({ name, baseUrl: BASE, io }, () =>
        run(new UnreachableHttp("ENOTFOUND"), io),
      );
      expect([code, err]).toEqual([1, [`unreachable ${BASE}: ENOTFOUND`]]);
    });

    it(`${name} puts the stack behind the debug switch`, async () => {
      const { io, err } = recorder();
      await runCommand({ name, baseUrl: BASE, io, debug: true }, () =>
        run(new UnreachableHttp(), io),
      );
      expect(err).toHaveLength(2);
      expect(err[1]).toContain("at ");
    });
  }
});

describe("the six write doors, wired to the wrapper and not around it", () => {
  // The behaviour above is driven through the exported runs, because a command's
  // `main` exits the process and is c8-ignored for that reason — so a run that
  // was unwired from `runCommand` would still pass every test above. This is
  // the other half: the entry point itself, read. A linter would hold it, and
  // this repository has none (decision D-011), so it is a test.
  const DOORS: readonly string[] = [
    "submit",
    "register",
    "dispute",
    "report",
    "revalidate",
    "reconfirm",
  ];

  for (const door of DOORS) {
    it(`${door} hands its run to the shared wrapper`, () => {
      const source = readFileSync(
        fileURLToPath(new URL(`../src/cli/${door}.ts`, import.meta.url)),
        "utf8",
      );

      expect(source).toMatch(
        /import \{[^}]*\brunCommand\b[^}]*\} from "\.\/main\.js";/,
      );
      // The wrapper is given the command's own name and the URL it was pointed
      // at, which is what the unreachable line is written from.
      expect(source).toMatch(
        new RegExp(`runCommand\\(\\s*\\{\\s*name: "${door}", baseUrl\\b`),
      );
      // And the catch-and-print it used to end with is gone: two sentences for
      // one failure is how the wording drifted apart in the first place.
      expect(source).not.toContain("`" + door + ": ${reasonOf(error)}`");
    });
  }
});

describe("the two mirror commands, which used to route around the wrapper", () => {
  // The QA of 2026-09-13: both entry points called their run directly and
  // caught nothing, so anything the run did not understand left the process as
  // a stack. Each is driven here exactly as its own entry point drives it.
  const MISSING = "/nonexistent/nomankind-mirror-that-is-not-there";

  it("verify-mirror says a directory it cannot read in one line", async () => {
    const { io, err, out } = recorder();
    const code = await runCommand(
      { name: "verify-mirror", baseUrl: null, io },
      () => verifyMirror([MISSING], io),
    );

    expect(code).toBe(1);
    expect(err).toHaveLength(1);
    expect(err[0]).toContain(MISSING);
    expect(err[0]).not.toContain("at ");
    expect(out).toEqual([]);
  });

  it("verify-mirror names an unreachable captures base, not undici's frame", async () => {
    const { io, err } = recorder();
    // The one URL this command fetches is the captures archive, so it is the
    // one the entry point hands the wrapper to name.
    const code = await runCommand(
      { name: "verify-mirror", baseUrl: BASE, io },
      async () => {
        throw fetchFailure("ENOTFOUND");
      },
    );

    expect([code, err]).toEqual([1, [`unreachable ${BASE}: ENOTFOUND`]]);
  });

  it("import-mirror says a database it cannot open in one line", async () => {
    const { io, err, out } = recorder();
    const code = await runCommand(
      { name: "import-mirror", baseUrl: null, io },
      () =>
        runImport([MISSING], io, async () => {
          throw Object.assign(new Error("no such file or directory"), {
            code: "ENOENT",
          });
        }),
    );

    expect(code).toBe(1);
    expect(err).toEqual([
      "import database_unavailable: no such file or directory",
    ]);
    expect(out).toEqual([]);
  });

  it("import-mirror lets nothing else escape as a stack either", async () => {
    const { io, err } = recorder();
    // What the run does not understand — a state directory another process
    // holds, thrown on the way out rather than on the way in — is the wrapper's
    // to name, and it names the command.
    const code = await runCommand(
      { name: "import-mirror", baseUrl: null, io },
      async () => {
        throw new Error("state directory is locked");
      },
    );

    expect([code, err]).toEqual([1, ["import-mirror: state directory is locked"]]);
  });
});
