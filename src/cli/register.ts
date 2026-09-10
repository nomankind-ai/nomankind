/**
 * register: an operator's own client for the joining door.
 *
 * Whitepaper Section 11: joining is three steps — publish a TXT record on a
 * domain you control carrying your 1F916 agent id, complete payout onboarding,
 * and sign the attestation that no model provider holds control or a beneficial
 * stake. Section 10 names the attestation; src/registry.ts holds its text and
 * its signing bytes.
 *
 * The TXT record is step one and it is not ours to make, so this command prints
 * exactly the line the operator has to publish before anything is asked of the
 * door — the same line `npm run checkpoint` prints for its fixtures — and then
 * asks. A registration refused with `dns_no_record` is that record missing, and
 * printing it first is what turns that refusal into an instruction.
 *
 * `--genesis` is Section 11's other half: "the maintainer names the first
 * operators trusted, and after genesis trust is earned." Only the maintainer's
 * key can do it, so it is a second key file and a second signed request, made
 * after the registration and only when the registration held.
 *
 * Nothing is decided here. The Worker resolves the TXT record itself, asks the
 * payment provider itself and verifies the attestation itself; this command
 * prints what it said.
 *
 * The core is exported over injected io — an http client, a clock and the keys —
 * so a test drives it in process against handleRequest with no network and no
 * DNS at all. `main` is thin. A private key is never printed. node:path is
 * allowed in this CLI file only.
 */

import { resolve } from "node:path";

import { MOCK_VERIFIED_PREFIX } from "../adapters/payout.js";
import { DEFAULT_DOMAIN } from "../policy.js";
import { signAttestation, txtRecordName } from "../registry.js";
import {
  errorOf,
  readKeyFile,
  reasonOf,
  signedPost,
  WebHttpClient,
  type HttpClient,
  type ValidatorIo,
  type ValidatorKey,
} from "./validator.js";

const USAGE =
  "usage: register <key.json> <base-url> <operator-domain> [--domain <slug>] [--genesis <maintainer-key.json>]\n" +
  "       register <key.json> <base-url> <operator-domain> --join <slug>";

/** Exit codes, named where they are decided rather than spelt at each return. */
const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/**
 * The payout reference this command sends.
 *
 * Not a policy number and not a rule: it is the mock adapter's own wire format
 * (src/adapters/payout.ts), which demo and local run and which production
 * refuses outright. Decision D-013 as amended puts the real provider in M25, and
 * until it exists there is no honest reference for this command to send but the
 * mock's — so it sends one that names the domain it is for, and production's
 * stub answers `payout_unavailable` rather than letting it through.
 */
export function payoutReferenceFor(domain: string): string {
  return `${MOCK_VERIFIED_PREFIX}${domain}`;
}

/** What one invocation asks for. */
export interface RegisterPlan {
  readonly keyPath: string;
  readonly baseUrl: string;
  /** The operator's own domain, which is also its id (Section 5). */
  readonly domain: string;
  /**
   * The registered domain the operator joins, and whose attestation it signs
   * (decision D-071). `--domain`, defaulting to ai-ecosystem: the only domain
   * there was before v0.7, so a command written then means the same thing.
   */
  readonly recordDomain: string;
  /**
   * `--join <slug>`: this run takes on a further domain instead of
   * registering. Null on an ordinary registration.
   */
  readonly join: string | null;
  /** The maintainer's key file, or null when this run only registers. */
  readonly genesisKeyPath: string | null;
}

/**
 * The registration one invocation asks for, or null when the arguments are not
 * one. Parsed before any I/O, so a bad invocation never touches the network.
 */
export function registerPlan(args: readonly string[]): RegisterPlan | null {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; ) {
    const argument = args[index];
    if (argument === undefined) return null;
    if (!argument.startsWith("--")) {
      positional.push(argument);
      index += 1;
      continue;
    }
    if (argument !== "--genesis" && argument !== "--domain" && argument !== "--join") {
      return null;
    }
    if (flags.has(argument)) return null;
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    flags.set(argument, value);
    index += 2;
  }

  const [keyPath, baseUrl, domain] = positional;
  if (
    keyPath === undefined ||
    baseUrl === undefined ||
    domain === undefined ||
    positional.length > 3
  ) {
    return null;
  }

  // A join is the whole run: the operator is registered already, so there is no
  // registration for `--domain` to name and no first membership for `--genesis`
  // to follow. Asking for both is asking for two different runs at once.
  const join = flags.get("--join") ?? null;
  if (join !== null && (flags.has("--domain") || flags.has("--genesis"))) {
    return null;
  }

  return {
    keyPath,
    baseUrl,
    domain,
    recordDomain: flags.get("--domain") ?? DEFAULT_DOMAIN,
    join,
    genesisKeyPath: flags.get("--genesis") ?? null,
  };
}

/** Everything a run needs besides its arguments. All of it injected. */
export interface RegisterDeps {
  readonly http: HttpClient;
  readonly now: Date;
  readonly io: ValidatorIo;
}

/** What one registration run did. */
export interface RegisterRun {
  /** The operator is registered, and named trusted when one was asked for. */
  readonly ok: boolean;
  /** The registry route's status. */
  readonly status: number | null;
  /** The refusal the route named, or null. */
  readonly error: string | null;
  /** Whether the operator was already there, which is not a failure. */
  readonly already: boolean;
  /** The genesis route's status, or null when none was asked for. */
  readonly genesisStatus: number | null;
  /** The genesis refusal, or null. */
  readonly genesisError: string | null;
}

/** What one join run did: the route's status, and the refusal it named. */
export interface JoinRun {
  readonly ok: boolean;
  readonly status: number;
  readonly error: string | null;
  /** Whether the operator was already in that domain, which is not a failure. */
  readonly already: boolean;
}

/** One signed POST, with its status and whatever JSON came back. */
async function post(
  deps: RegisterDeps,
  baseUrl: string,
  path: string,
  body: unknown,
  key: ValidatorKey,
): Promise<{ status: number; body: unknown }> {
  const request = await signedPost({ baseUrl, path, body, key, now: deps.now });
  const response = await deps.http.fetch(request);
  let parsed: unknown = null;
  try {
    parsed = await response.json();
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed };
}

/**
 * Register one operator, and name it trusted when a maintainer key was given.
 *
 * A registration that is already there is not a failure: an operator rerunning
 * the command against a demo it has already joined is told so and the run
 * carries on, exactly as the checkpoint treats its own repeats.
 */
export async function runRegister(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly domain: string;
  /**
   * The registered domain to join and attest to (decision D-071). Absent is
   * ai-ecosystem, which is what a client written before v0.7 meant.
   */
  readonly recordDomain?: string;
  readonly genesisKey?: ValidatorKey | null;
  readonly deps: RegisterDeps;
}): Promise<RegisterRun> {
  const { deps } = input;
  const at = deps.now.toISOString();
  const recordDomain = input.recordDomain ?? DEFAULT_DOMAIN;

  // Step one, and it is not ours to make: the record the operator publishes.
  deps.io.stdout(
    `txt ${txtRecordName(input.domain)} TXT ${input.key.agentId}`,
  );

  // The attestation is that domain's own sentence under that domain's version
  // (decision D-071): src/registry.ts reads both out of the registry document's
  // table, so this command never spells either.
  const attestation = await signAttestation(input.key.privateKey, {
    operator: input.domain,
    agent: input.key.agentId,
    domain: recordDomain,
    signed_at: at,
  });
  const registered = await post(
    deps,
    input.baseUrl,
    "/operators",
    {
      operator: input.domain,
      domain: recordDomain,
      attestation,
      payout: { reference: payoutReferenceFor(input.domain) },
    },
    input.key,
  );
  const error = errorOf(registered.body);
  const already =
    registered.status === 409 &&
    (error === "operator_exists" || error === "agent_bound");
  const joined = registered.status === 201 || already;

  deps.io.stdout(
    `register ${input.domain} ${recordDomain} ${registered.status}${error === null ? "" : ` ${error}`}`,
  );
  if (!joined) {
    return {
      ok: false,
      status: registered.status,
      error,
      already: false,
      genesisStatus: null,
      genesisError: null,
    };
  }

  const genesisKey = input.genesisKey ?? null;
  if (genesisKey === null) {
    return {
      ok: true,
      status: registered.status,
      error: already ? error : null,
      already,
      genesisStatus: null,
      genesisError: null,
    };
  }

  // Section 11: "the maintainer names the first operators trusted." Only the
  // maintainer's key may, so this is a second signed request under a second key.
  const named = await post(
    deps,
    input.baseUrl,
    "/genesis",
    { operator: input.domain },
    genesisKey,
  );
  const genesisError = errorOf(named.body);
  const alreadyTrusted =
    named.status === 409 && genesisError === "already_trusted";
  const trusted = named.status === 200 || alreadyTrusted;

  deps.io.stdout(
    `genesis ${input.domain} ${named.status}${genesisError === null ? "" : ` ${genesisError}`}`,
  );
  if (!trusted) deps.io.stderr(`genesis: ${genesisError ?? "unknown error"}`);

  return {
    ok: trusted,
    status: registered.status,
    error: already ? error : null,
    already,
    genesisStatus: named.status,
    genesisError,
  };
}

/**
 * Take on a further domain: sign that domain's attestation and post the join.
 *
 * Decision D-071: registration binds an operator to its first domain, and every
 * later one is a separate signed act at its own door. The operator id is the
 * same domain the operator already registered under; what is new is the record
 * domain it is attesting to.
 *
 * A domain the operator already holds is not a failure, for the reason a repeat
 * registration is not: the command is idempotent so an operator can rerun it.
 */
export async function runJoin(input: {
  readonly key: ValidatorKey;
  readonly baseUrl: string;
  readonly domain: string;
  /** The registered domain being joined. */
  readonly join: string;
  readonly deps: RegisterDeps;
}): Promise<JoinRun> {
  const { deps } = input;
  const attestation = await signAttestation(input.key.privateKey, {
    operator: input.domain,
    agent: input.key.agentId,
    domain: input.join,
    signed_at: deps.now.toISOString(),
  });
  const joined = await post(
    deps,
    input.baseUrl,
    `/operators/${encodeURIComponent(input.domain)}/domains`,
    { domain: input.join, attestation },
    input.key,
  );
  const error = errorOf(joined.body);
  const already = joined.status === 409 && error === "already_joined";
  deps.io.stdout(
    `join ${input.domain} ${input.join} ${joined.status}${error === null ? "" : ` ${error}`}`,
  );
  const ok = joined.status === 201 || already;
  if (!ok) deps.io.stderr(`join: ${error ?? "unknown error"}`);
  return { ok, status: joined.status, error, already };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const plan = registerPlan(process.argv.slice(2));
  if (plan === null) {
    console.error(USAGE);
    process.exit(BAD_ARGUMENTS);
  }

  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  let code: number = FAILED;
  try {
    const deps = { http: new WebHttpClient(), now: new Date(), io };
    const run =
      plan.join === null
        ? await runRegister({
            key: await readKeyFile(plan.keyPath),
            baseUrl: plan.baseUrl,
            domain: plan.domain,
            recordDomain: plan.recordDomain,
            genesisKey:
              plan.genesisKeyPath === null
                ? null
                : await readKeyFile(plan.genesisKeyPath),
            deps,
          })
        : await runJoin({
            key: await readKeyFile(plan.keyPath),
            baseUrl: plan.baseUrl,
            domain: plan.domain,
            join: plan.join,
            deps,
          });
    code = run.ok ? OK : FAILED;
  } catch (error) {
    io.stderr(`register: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */
