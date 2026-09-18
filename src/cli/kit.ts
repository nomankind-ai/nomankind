/**
 * kit: the reader's whole command line, and no key anywhere in it.
 *
 * Whitepaper, The training path: a learner reads one fact, walks the delta
 * stream from where they left off, and checks the proof offline. Decision D-131
 * item 4 says they do all three without a key, and decision D-127 item 4b says
 * every fact they are handed travels with who signed it. So the attribution is
 * printed after every fact by default and `--no-attribution` is the way to
 * silence it — the other way round would be a record that made citing the
 * validator the thing you had to remember to ask for.
 *
 * Six verbs over src/kit/client.ts and nothing else:
 *
 *   kit read <base> <entry id>            one fact, by id
 *   kit read <base> --subject … --category …
 *   kit sync <base> [--from n] [--limit n] [--pages n]
 *   kit attribution <base> <entry id>
 *   kit export <base> <entry id> <dir> [--bounded]
 *   kit verify <entry.json> <log.json>
 *   kit cite <base> <entry id>
 *
 * `--json` prints the answer as one object for a machine and nothing else, so a
 * script never has to parse these lines.
 *
 * The exit code is the answer: 0 when the door answered, 1 when it refused or
 * the proof did not hold, 2 when the command was called wrong. A stranger's
 * deployment is data, never a crash: every refusal is one named line.
 *
 * node:path is allowed in this CLI file only.
 */

import { resolve } from "node:path";

import type { Attribution } from "../attribution.js";
import {
  createReader,
  ReaderRefusal,
  type ReadAnswer,
  type Reader,
  type SyncItem,
} from "../kit/client.js";
import { runCommand } from "./main.js";
import type { ValidatorIo } from "./validator.js";

const USAGE = [
  "usage: kit read <base-url> <entry-id> [--no-attribution] [--json]",
  "       kit read <base-url> --subject <s> --category <c> [--domain <d>] [--min-tier <t>] [--min-class <c>] [--max-age <days>] [--no-attribution] [--json]",
  "       kit sync <base-url> [--from <n>] [--limit <n>] [--pages <n>] [--domain <d>] [--min-tier <t>] [--min-class <c>] [--no-attribution] [--json]",
  "       kit attribution <base-url> <entry-id> [--json]",
  "       kit export <base-url> <entry-id> <out-dir> [--bounded]",
  "       kit verify <entry.json> <log-bundle.json> [--json]",
  "       kit cite <base-url> <entry-id>",
].join("\n");

const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/** The verbs, so an unknown one is refused rather than guessed at. */
export const KIT_VERBS = [
  "read",
  "sync",
  "attribution",
  "export",
  "verify",
  "cite",
] as const;

export type KitVerb = (typeof KIT_VERBS)[number];

export function isKitVerb(value: unknown): value is KitVerb {
  return (
    typeof value === "string" && (KIT_VERBS as readonly string[]).includes(value)
  );
}

/**
 * The base `kit verify` is given, which it never reads.
 *
 * The offline verifier touches no door — that is what makes it the paper's one
 * script — but it is reached through the same client as every other verb, so
 * there is one place the kit's behaviour lives. An unroutable name rather than
 * a real one, so a bug that made it fetch would fail loudly instead of quietly
 * reading production.
 */
export const OFFLINE_BASE = "https://offline.invalid";

/** Flags that take no value. */
const SWITCHES = ["--no-attribution", "--json", "--bounded"];

interface Parsed {
  readonly positional: readonly string[];
  readonly values: ReadonlyMap<string, string>;
  readonly switches: ReadonlySet<string>;
}

/**
 * The arguments, split into positionals, valued flags and switches, or null
 * when they are not a command.
 *
 * Refuses rather than guesses: a flag with no value and a value that looks like
 * a flag are both a caller who meant something this command cannot see, and
 * answering them with a default would be answering a question nobody asked.
 */
export function parseArgs(args: readonly string[]): Parsed | null {
  const positional: string[] = [];
  const values = new Map<string, string>();
  const switches = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    if (SWITCHES.includes(arg)) {
      if (switches.has(arg)) return null;
      switches.add(arg);
      continue;
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    if (values.has(arg)) return null;
    values.set(arg, value);
    index += 1;
  }
  return { positional, values, switches };
}

/** Every flag a verb knows; anything else is a refusal. */
const KNOWN: Readonly<Record<KitVerb, readonly string[]>> = Object.freeze({
  read: [
    "--subject",
    "--category",
    "--domain",
    "--min-tier",
    "--min-class",
    "--max-age",
  ],
  sync: ["--from", "--limit", "--pages", "--domain", "--min-tier", "--min-class"],
  attribution: [],
  export: [],
  verify: [],
  cite: [],
});

/** The attribution block, as the lines a reader reads. */
export function attributionLines(block: Attribution | null): string[] {
  if (block === null) return ["cite: (no attribution)"];
  const lines = [`cite: ${block.citation}`];
  lines.push(
    `author: ${block.author.agent}${
      block.author.operator === null ? "" : ` (${block.author.operator})`
    }`,
  );
  for (const row of block.validators) {
    lines.push(
      `validator: ${row.agent} ${row.operator} ${row.kind} ${row.decision}${
        row.assigned_random ? " assigned" : ""
      }`,
    );
  }
  for (const row of block.reconfirmers) {
    lines.push(`reconfirmer: ${row.agent} ${row.operator} ${row.kind} ${row.at}`);
  }
  return lines;
}

/** One fact, as the lines a reader reads. */
function factLines(answer: ReadAnswer, withAttribution: boolean): string[] {
  const claim = answer.entry["claim"];
  const lines = [
    `${answer.entry_id} ${typeof claim === "string" ? claim : "(no claim)"}`,
    [
      `status ${answer.status ?? "unknown"}`,
      `tier ${answer.effective_tier ?? "none"}`,
      `class ${answer.verification_class ?? "none"}`,
      `receipt ${answer.receipted ? "yes" : "no"}`,
    ].join(" "),
  ];
  if (withAttribution) lines.push(...attributionLines(answer.attribution));
  return lines;
}

/** One stream item, as the lines a reader reads. */
function itemLines(item: SyncItem, withAttribution: boolean): string[] {
  const lines = [
    [
      `seq ${item.seq}`,
      item.kind,
      item.entry_id ?? "-",
      `status ${item.status ?? "-"}`,
      `class ${item.verification_class ?? "-"}`,
    ].join(" "),
  ];
  if (withAttribution && item.attribution !== null) {
    lines.push(`cite: ${item.citation ?? "(no attribution)"}`);
  }
  return lines;
}

/**
 * Run one invocation and answer its exit code.
 *
 * The reader is injectable so a test drives every verb in process against a
 * recorded door with no network.
 */
export async function runKit(
  args: readonly string[],
  io: ValidatorIo,
  makeReader: (base: string) => Reader = (base) => createReader({ base }),
): Promise<number> {
  const verb = args[0];
  if (!isKitVerb(verb)) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  const parsed = parseArgs(args.slice(1));
  if (parsed === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  for (const flag of parsed.values.keys()) {
    if (!KNOWN[verb].includes(flag)) {
      io.stderr(USAGE);
      return BAD_ARGUMENTS;
    }
  }

  const asJson = parsed.switches.has("--json");
  const withAttribution = !parsed.switches.has("--no-attribution");
  const print = (lines: readonly string[], data: unknown): number => {
    if (asJson) io.stdout(JSON.stringify(data, null, 2));
    else for (const line of lines) io.stdout(line);
    return OK;
  };

  if (verb === "verify") {
    const [entryPath, logPath] = parsed.positional;
    if (entryPath === undefined || logPath === undefined) {
      io.stderr(USAGE);
      return BAD_ARGUMENTS;
    }
    const reader = makeReader(OFFLINE_BASE);
    let report;
    try {
      report = await reader.verify(resolve(entryPath), resolve(logPath));
    } catch (error) {
      io.stderr(`verify: ${error instanceof Error ? error.message : "failed"}`);
      return FAILED;
    }
    const lines = [
      report.ok ? "ok" : "failed",
      `entry ${report.entry_id ?? "unknown"}`,
      `diffs ${report.diffs.length}`,
      `bundle ${report.bounded ? "bounded" : "full"}`,
      ...report.diffs.map(
        (diff) => `${diff.check} ${diff.field} ${diff.reason}`,
      ),
      ...(report.not_run.length === 0
        ? []
        : [`not run: ${report.not_run.join(", ")}`]),
    ];
    print(lines, report);
    return report.ok ? OK : FAILED;
  }

  const base = parsed.positional[0];
  if (base === undefined) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  const reader = makeReader(base);

  try {
    if (verb === "read") {
      const id = parsed.positional[1];
      const subject = parsed.values.get("--subject");
      const category = parsed.values.get("--category");
      if (id === undefined && (subject === undefined || category === undefined)) {
        io.stderr(USAGE);
        return BAD_ARGUMENTS;
      }
      const maxAge = parsed.values.get("--max-age");
      const domain = parsed.values.get("--domain");
      const minTier = parsed.values.get("--min-tier");
      const minClass = parsed.values.get("--min-class");
      const answer =
        id !== undefined
          ? await reader.read(id)
          : await reader.read({
              subject: subject!,
              category: category!,
              ...(domain === undefined ? {} : { domain }),
              ...(minTier === undefined ? {} : { min_tier: minTier }),
              ...(minClass === undefined ? {} : { min_class: minClass }),
              ...(maxAge === undefined ? {} : { max_age: maxAge }),
            });
      return print(factLines(answer, withAttribution), answer);
    }

    if (verb === "sync") {
      const from = Number(parsed.values.get("--from") ?? "0");
      const limit = Number(parsed.values.get("--limit") ?? "50");
      const pagesFlag = parsed.values.get("--pages");
      const pages = pagesFlag === undefined ? null : Number(pagesFlag);
      if (
        !Number.isSafeInteger(from) ||
        from < 0 ||
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        // A page count that is not a whole number of pages is a demand this
        // command cannot meet: `--pages 0` and `--pages half` would both walk
        // the whole stream, which is the opposite of what they asked for.
        (pages !== null && (!Number.isSafeInteger(pages) || pages < 1))
      ) {
        io.stderr(USAGE);
        return BAD_ARGUMENTS;
      }
      const domain = parsed.values.get("--domain");
      const minTier = parsed.values.get("--min-tier");
      const minClass = parsed.values.get("--min-class");
      const items: SyncItem[] = [];
      for await (const item of reader.sync({
        from,
        limit,
        ...(pages === null ? {} : { pages }),
        ...(domain === undefined ? {} : { domain }),
        ...(minTier === undefined ? {} : { min_tier: minTier }),
        ...(minClass === undefined ? {} : { min_class: minClass }),
      })) {
        items.push(item);
      }
      const head =
        items.length === 0 ? from : (items[items.length - 1]!.page_head ?? from);
      return print(
        [
          `from ${from} head ${head} items ${items.length}`,
          ...items.flatMap((item) => itemLines(item, withAttribution)),
        ],
        { from, head, items },
      );
    }

    if (verb === "attribution" || verb === "cite") {
      const id = parsed.positional[1];
      if (id === undefined) {
        io.stderr(USAGE);
        return BAD_ARGUMENTS;
      }
      const block = await reader.attribution(id);
      return verb === "cite"
        ? print([reader.cite(block)], { citation: block.citation })
        : print(attributionLines(block), block);
    }

    // export
    const id = parsed.positional[1];
    const dir = parsed.positional[2];
    if (id === undefined || dir === undefined) {
      io.stderr(USAGE);
      return BAD_ARGUMENTS;
    }
    const written = await reader.exportBundle(id, dir, {
      bounded: parsed.switches.has("--bounded"),
    });
    return print(
      [
        `entry ${written.entryPath}`,
        `log ${written.bundlePath}`,
        `attribution ${written.attributionPath}`,
      ],
      written,
    );
  } catch (error) {
    if (error instanceof ReaderRefusal) {
      io.stdout(`refused ${error.status} ${error.reason} ${error.path}`);
      return FAILED;
    }
    throw error;
  }
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const args = process.argv.slice(2);
  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  process.exit(
    await runCommand(
      { name: "kit", baseUrl: args[1] ?? null, io },
      () => runKit(args, io),
    ),
  );
}
/* c8 ignore stop */
