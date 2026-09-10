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
  "usage: register <key.json> <base-url> <domain> [--genesis <maintainer-key.json>]";

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
  readonly domain: string;
  /** The maintainer's key file, or null when this run only registers. */
  readonly genesisKeyPath: string | null;
}

/**
 * The registration one invocation asks for, or null when the arguments are not
 * one. Parsed before any I/O, so a bad invocation never touches the network.
 */
export function registerPlan(args: readonly string[]): RegisterPlan | null {
  const positional: string[] = [];
  let genesisKeyPath: string | undefined;
  for (let index = 0; index < args.length; ) {
    const argument = args[index];
    if (argument === undefined) return null;
    if (!argument.startsWith("--")) {
      positional.push(argument);
      index += 1;
      continue;
    }
    if (argument !== "--genesis") return null;
    if (genesisKeyPath !== undefined) return null;
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) return null;
    genesisKeyPath = value;
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
  return { keyPath, baseUrl, domain, genesisKeyPath: genesisKeyPath ?? null };
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
  readonly genesisKey?: ValidatorKey | null;
  readonly deps: RegisterDeps;
}): Promise<RegisterRun> {
  const { deps } = input;
  const at = deps.now.toISOString();

  // Step one, and it is not ours to make: the record the operator publishes.
  deps.io.stdout(
    `txt ${txtRecordName(input.domain)} TXT ${input.key.agentId}`,
  );

  const attestation = await signAttestation(input.key.privateKey, {
    operator: input.domain,
    agent: input.key.agentId,
    signed_at: at,
  });
  const registered = await post(
    deps,
    input.baseUrl,
    "/operators",
    {
      operator: input.domain,
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
    `register ${input.domain} ${registered.status}${error === null ? "" : ` ${error}`}`,
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
    const run = await runRegister({
      key: await readKeyFile(plan.keyPath),
      baseUrl: plan.baseUrl,
      domain: plan.domain,
      genesisKey:
        plan.genesisKeyPath === null
          ? null
          : await readKeyFile(plan.genesisKeyPath),
      deps: { http: new WebHttpClient(), now: new Date(), io },
    });
    code = run.ok ? OK : FAILED;
  } catch (error) {
    io.stderr(`register: ${reasonOf(error)}`);
  }
  process.exit(code);
}
/* c8 ignore stop */
