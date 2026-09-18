/**
 * The confirm command: the line, the signature, the fingerprint, the refusals.
 *
 * Decision D-138 item 6 is one command that generates or loads a key, signs the
 * line and prints the comment and the profile line. What these tests hold it to
 * is that the line it composes is the line the door reads back — the same
 * canonical spelling, the same token order, the same fingerprint — because a
 * confirmer whose command composed a line the sweep does not recognise has done
 * the work and had it counted as prose.
 *
 * The cited source is served from the committed verify fixture's own capture,
 * so the reproduced path is a real norm-v1.2 hash of real bytes and not a
 * stubbed comparison.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { FetchResult, SnapshotFetcher } from "../src/adapters/fetch.js";
import {
  canonicalConfirmationLine,
  confirmationFingerprint,
  parseConfirmationLine,
  profileKeyIn,
  verifyLineSignature,
} from "../src/confirm.js";
import { base64Decode, base64urlEncode } from "../src/encoding.js";
import {
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { generatedKeyPath, runConfirm } from "../src/cli/confirm.js";
import { defaultKeyPath, keyDirectory } from "../src/cli/keygen.js";
import type { Reader } from "../src/kit/client.js";
import {
  hasEmailAddress,
  prepareConfirmation,
  SEAL_LABEL,
  type ConfirmKey,
} from "../src/kit/confirm.js";
import { ATTESTATION_VERSION } from "../src/registry.js";

const BASE = "https://app.nomankind.ai";
const FIXTURES = join(import.meta.dirname, "fixtures", "verify");

type Json = Record<string, unknown>;

async function fixture(name: string): Promise<Json> {
  return JSON.parse(await readFile(join(FIXTURES, name), "utf8")) as Json;
}

/** The entry, and the very bytes its snapshot hash was taken over. */
async function world(): Promise<{
  entry: Json;
  entryId: string;
  bytes: Uint8Array;
  contentType: string | null;
}> {
  const entry = await fixture("verified-entry.json");
  const bundle = await fixture("log.json");
  const captures = bundle["captures"] as Record<string, Json>;
  const capture = captures[entry["snapshot_hash"] as string]!;
  return {
    entry,
    entryId: entry["id"] as string,
    bytes: base64Decode(capture["body_base64"] as string),
    contentType: (capture["content_type"] as string | null) ?? null,
  };
}

/** A key in the shape `npm run keygen` writes, private half included. */
async function makeKey(): Promise<ConfirmKey> {
  const pair = await generateKeypair();
  return {
    agent_id: null,
    public_key: base64urlEncode(await exportPublicKeyRaw(pair.publicKey)),
    private_key_pkcs8: base64urlEncode(
      await exportPrivateKeyPkcs8(pair.privateKey),
    ),
  };
}

/** A fetcher that always answers the same bytes. */
function fetcherFor(
  bytes: Uint8Array,
  contentType: string | null,
): SnapshotFetcher {
  return {
    async fetch(url: string): Promise<FetchResult> {
      return {
        ok: true,
        bytes,
        status: 200,
        headers: contentType === null ? {} : { "content-type": contentType },
        finalUrl: url,
      };
    },
  };
}

/** A fetcher that never reaches anything. */
const unreachable: SnapshotFetcher = {
  async fetch(): Promise<FetchResult> {
    return { ok: false, reason: "fetch_failed" };
  },
};

/** The entry door, and nothing else. */
function entryDoor(entry: Json | null) {
  return async (path: string): Promise<{ status: number; body: unknown }> =>
    entry === null || !path.startsWith("/entries/")
      ? { status: 404, body: { error: "not_found" } }
      : { status: 200, body: entry };
}

describe("confirm: the canonical line and its signature", () => {
  it("signs the canonical line, and the signature verifies under the profile key", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();

    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "colony",
        verdict: null,
        check: null,
        attest: false,
        reason: "fetched it myself",
        key,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(bytes, contentType) },
    );

    expect(result.canonical_line).toBe(
      canonicalConfirmationLine({
        entry_id: entryId,
        verdict: result.verdict,
        check: result.check,
      }),
    );
    // The signature is over the canonical line and never over the comment: the
    // reason is the confirmer's prose and no part of the claim.
    const parsed = parseConfirmationLine(result.comment_line, 0, () => true);
    expect(parsed).not.toBeNull();
    expect(parsed!.signature).not.toBeNull();
    expect(
      await verifyLineSignature(
        key.public_key,
        result.canonical_line,
        parsed!.signature!,
      ),
    ).toBe(true);
    expect(parsed!.reason).toBe("fetched it myself");
  });

  it("prints the profile line the venue's bio carries, and no fingerprint", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();
    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "github",
        verdict: null,
        check: null,
        attest: false,
        reason: null,
        key,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(bytes, contentType) },
    );

    expect(result.profile_line).not.toBeNull();
    expect(profileKeyIn(result.profile_line!)).toBe(key.public_key);
    expect(result.fingerprint).toBeNull();
    expect(result.seal_request).toBeNull();
    expect(result.binding).toBe("profile");
  });

  it("puts the attestation token inside what is signed", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();
    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "colony",
        verdict: null,
        check: null,
        attest: true,
        reason: null,
        key,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(bytes, contentType) },
    );

    expect(result.canonical_line).toContain(`attest:${ATTESTATION_VERSION}`);
    const parsed = parseConfirmationLine(result.comment_line, 0, () => true);
    expect(parsed!.attestation_version).toBe(ATTESTATION_VERSION);
    expect(
      await verifyLineSignature(
        key.public_key,
        result.canonical_line,
        parsed!.signature!,
      ),
    ).toBe(true);
  });
});

describe("confirm: the founding registry's fingerprint", () => {
  it("prints the fingerprint and the seal request, and signs nothing in the line", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "1f916",
        verdict: null,
        check: null,
        attest: false,
        reason: null,
        key: null,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(bytes, contentType) },
    );

    expect(result.binding).toBe("registry");
    expect(result.comment_line).toBe(result.canonical_line);
    expect(result.profile_line).toBeNull();
    expect(result.fingerprint).toBe(
      await confirmationFingerprint({
        entry_id: entryId,
        verdict: result.verdict,
        check: result.check,
      }),
    );
    const seal = result.seal_request!;
    expect(seal.method).toBe("POST");
    expect(seal.url).toBe("https://1f916.ai/api/seal");
    expect(seal.body.label).toBe(SEAL_LABEL);
    expect(seal.body.hash).toBe(result.fingerprint!.slice("sha256:".length));
    expect(seal.signature_preimage).toContain("1f916.seal.v1:");
    expect(seal.signature_preimage).toContain(seal.body.hash);
  });
});

describe("confirm: what the check decides", () => {
  it("approves when its own hash reproduces the entry's snapshot", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "1f916",
        verdict: null,
        check: null,
        attest: false,
        reason: null,
        key: null,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(bytes, contentType) },
    );
    expect(result.own_hash).toBe(entry["snapshot_hash"]);
    expect(result.reproduced).toBe(true);
    expect(result.verdict).toBe("approve");
    expect(result.forced).toBe(false);
    expect(result.check.kind).toBe("hash");
  });

  it("rejects when its own hash does not reproduce it", async () => {
    const { entry, entryId } = await world();
    const moved = new TextEncoder().encode(
      "the page now says something else entirely",
    );
    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "1f916",
        verdict: null,
        check: null,
        attest: false,
        reason: null,
        key: null,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(moved, "text/plain") },
    );
    expect(result.own_hash).not.toBe(entry["snapshot_hash"]);
    expect(result.reproduced).toBe(false);
    expect(result.verdict).toBe("reject");
    // The line carries the hash this confirmer actually got, which is the
    // statement it is making.
    expect(result.check).toEqual({ kind: "hash", value: result.own_hash });
  });

  it("says so when the confirmer overruled the check", async () => {
    const { entry, entryId } = await world();
    const moved = new TextEncoder().encode("moved");
    const result = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "1f916",
        verdict: "approve",
        check: null,
        attest: false,
        reason: null,
        key: null,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(moved, "text/plain") },
    );
    expect(result.reproduced).toBe(false);
    expect(result.verdict).toBe("approve");
    expect(result.forced).toBe(true);
  });

  it("checks the span the way the validator checks it", async () => {
    const { entry, entryId } = await world();
    // The quotation rule's question: does the page carry the entry's claim
    // verbatim, in the norm rule's own spelling. A page that does.
    const quoting = new TextEncoder().encode(
      `pricing notes\n\n${entry["claim"] as string}\n\nend`,
    );
    const present = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "1f916",
        verdict: null,
        check: "span-present",
        attest: false,
        reason: null,
        key: null,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(quoting, "text/plain") },
    );
    expect(present.check).toEqual({ kind: "span", value: "present" });
    expect(present.reproduced).toBe(true);
    expect(present.verdict).toBe("approve");

    const elsewhere = new TextEncoder().encode("nothing of the sort is here");
    const absent = await prepareConfirmation(
      {
        baseUrl: BASE,
        entryId,
        venue: "1f916",
        verdict: null,
        check: "span-present",
        attest: false,
        reason: null,
        key: null,
      },
      { get: entryDoor(entry), fetcher: fetcherFor(elsewhere, "text/plain") },
    );
    expect(absent.reproduced).toBe(false);
    expect(absent.verdict).toBe("reject");
  });
});

describe("confirm: the refusals", () => {
  const io = () => {
    const out: string[] = [];
    const err: string[] = [];
    return {
      out,
      err,
      io: {
        stdout: (line: string) => out.push(line),
        stderr: (line: string) => err.push(line),
      },
    };
  };

  /** A reader whose only door is the entry one. */
  function readerFor(entry: Json | null): Reader {
    const get = entryDoor(entry);
    return {
      base: BASE,
      fetchJson: get,
      read: () => Promise.reject(new Error("not used")),
      sync: (() => {
        throw new Error("not used");
      }) as unknown as Reader["sync"],
      attribution: () => Promise.reject(new Error("not used")),
      exportBundle: () => Promise.reject(new Error("not used")),
      verify: () => Promise.reject(new Error("not used")),
      cite: () => "",
    };
  }

  it("refuses an entry this record does not hold", async () => {
    const { out, io: sink } = io();
    const code = await runConfirm(
      [BASE, "nmk_01NOTHERE", "--venue", "1f916"],
      sink,
      { makeReader: () => readerFor(null), fetcher: unreachable },
    );
    expect(code).toBe(1);
    expect(out.join("\n")).toContain("unknown_entry");
  });

  it("refuses a source it could not reach", async () => {
    const { entry, entryId } = await world();
    const { out, io: sink } = io();
    const code = await runConfirm([BASE, entryId, "--venue", "1f916"], sink, {
      makeReader: () => readerFor(entry),
      fetcher: unreachable,
    });
    expect(code).toBe(1);
    expect(out.join("\n")).toContain("unreachable_source");
  });

  it("refuses a venue nobody publishes", async () => {
    const { entry, entryId } = await world();
    const { out, io: sink } = io();
    const code = await runConfirm(
      [BASE, entryId, "--venue", "somewhere-else"],
      sink,
      { makeReader: () => readerFor(entry), fetcher: unreachable },
    );
    expect(code).toBe(1);
    expect(out.join("\n")).toContain("unknown_venue");
  });

  it("refuses a reason carrying an email address", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();
    const { out, io: sink } = io();
    const code = await runConfirm(
      [
        BASE,
        entryId,
        "--venue",
        "colony",
        "--generate",
        "/unused/key.json",
        "--reason",
        "write to me at alice@example.com",
      ],
      sink,
      {
        makeReader: () => readerFor(entry),
        fetcher: fetcherFor(bytes, contentType),
        generateKey: async () => key,
      },
    );
    expect(code).toBe(1);
    expect(out.join("\n")).toContain("reason_has_email");
    expect(hasEmailAddress("no address here")).toBe(false);
  });

  it("refuses a profile venue with no key, and a registry venue with one", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();
    const first = io();
    expect(
      await runConfirm([BASE, entryId, "--venue", "colony"], first.io, {
        makeReader: () => readerFor(entry),
        fetcher: fetcherFor(bytes, contentType),
      }),
    ).toBe(1);
    expect(first.out.join("\n")).toContain("key_required");

    const second = io();
    expect(
      await runConfirm(
        [BASE, entryId, "--venue", "1f916", "--generate", "/unused/key.json"],
        second.io,
        {
          makeReader: () => readerFor(entry),
          fetcher: fetcherFor(bytes, contentType),
          generateKey: async () => key,
        },
      ),
    ).toBe(1);
    expect(second.out.join("\n")).toContain("key_unused");
  });

  it("refuses arguments that are not a confirmation, before any I/O", async () => {
    const { err, io: sink } = io();
    expect(await runConfirm([], sink)).toBe(2);
    expect(await runConfirm([BASE, "nmk_01X"], sink)).toBe(2);
    expect(
      await runConfirm([BASE, "nmk_01X", "maybe", "--venue", "1f916"], sink),
    ).toBe(2);
    expect(
      await runConfirm(
        [BASE, "nmk_01X", "--venue", "1f916", "--check", "vibes"],
        sink,
      ),
    ).toBe(2);
    expect(err.length).toBeGreaterThan(0);
  });
});

describe("confirm: the command's own lines", () => {
  it("prints the comment line, the profile line, and that nothing was posted", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();
    const out: string[] = [];
    const get = entryDoor(entry);
    const reader = {
      base: BASE,
      fetchJson: get,
    } as unknown as Reader;

    const code = await runConfirm(
      [
        BASE,
        entryId,
        "--venue",
        "colony",
        "--generate",
        "/unused/key.json",
        "--attest",
      ],
      { stdout: (line: string) => out.push(line), stderr: () => {} },
      {
        makeReader: () => reader,
        fetcher: fetcherFor(bytes, contentType),
        generateKey: async () => key,
      },
    );

    expect(code).toBe(0);
    const printed = out.join("\n");
    expect(printed).toContain("comment:");
    expect(printed).toContain("nomankind-key:");
    expect(printed).toContain("nothing was posted.");
    // The private half never appears in what the command printed.
    expect(printed).not.toContain(key.private_key_pkcs8);
  });
});

describe("confirm: where --generate writes", () => {
  it("resolves a bare name under the directory keygen writes to", () => {
    const home = "/home/agent";
    expect(generatedKeyPath("colony", home, "/work/nomankind")).toBe(
      defaultKeyPath("colony", home),
    );
    expect(generatedKeyPath("colony", home, "/work/nomankind")).toContain(
      keyDirectory(home),
    );
  });

  it("takes an explicit path outside the tree as given", () => {
    const home = "/home/agent";
    expect(
      generatedKeyPath("/home/agent/elsewhere/k.json", home, "/work/nomankind"),
    ).toBe("/home/agent/elsewhere/k.json");
  });

  it("refuses a path inside the working tree, in one sentence", () => {
    const home = "/home/agent";
    for (const inside of ["./keys/k.json", "src/k.json", "."]) {
      let raised: unknown = null;
      try {
        generatedKeyPath(inside, home, "/work/nomankind");
      } catch (error) {
        raised = error;
      }
      expect(raised, inside).toBeInstanceOf(Error);
      expect((raised as Error).message).toContain("key_in_tree");
      expect((raised as Error).message).toContain("inside the working tree");
      expect((raised as Error).message).toContain(keyDirectory(home));
    }
  });

  it("writes no key at all when the venue never wanted one", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const asked: string[] = [];
    const out: string[] = [];

    const code = await runConfirm(
      [BASE, entryId, "--venue", "1f916", "--generate", "colony"],
      { stdout: (line: string) => out.push(line), stderr: () => {} },
      {
        makeReader: () =>
          ({ base: BASE, fetchJson: entryDoor(entry) }) as unknown as Reader,
        fetcher: fetcherFor(bytes, contentType),
        generateKey: async (path: string) => {
          asked.push(path);
          return makeKey();
        },
      },
    );

    expect(code).toBe(1);
    expect(out.join("\n")).toContain("key_unused");
    // The refusal came before anything was generated: a confirmer told their
    // key was never needed must not find one on their disk.
    expect(asked).toEqual([]);
  });

  it("hands the generator the path keygen would have chosen", async () => {
    const { entry, entryId, bytes, contentType } = await world();
    const key = await makeKey();
    const asked: string[] = [];
    const out: string[] = [];

    const code = await runConfirm(
      [BASE, entryId, "--venue", "colony", "--generate", "colony"],
      { stdout: (line: string) => out.push(line), stderr: () => {} },
      {
        makeReader: () =>
          ({ base: BASE, fetchJson: entryDoor(entry) }) as unknown as Reader,
        fetcher: fetcherFor(bytes, contentType),
        generateKey: async (path: string) => {
          asked.push(path);
          return key;
        },
      },
    );

    expect(code).toBe(0);
    expect(asked).toEqual([defaultKeyPath("colony")]);
    // Outside the repository, which is where every key this record makes goes.
    expect(asked[0]!.startsWith(process.cwd())).toBe(false);
  });

  it("refuses --generate into the working tree before fetching anything", async () => {
    const { entry, entryId } = await world();
    const out: string[] = [];
    let fetched = 0;
    const code = await runConfirm(
      [BASE, entryId, "--venue", "colony", "--generate", "./key.json"],
      { stdout: (line: string) => out.push(line), stderr: () => {} },
      {
        makeReader: () =>
          ({ base: BASE, fetchJson: entryDoor(entry) }) as unknown as Reader,
        fetcher: {
          async fetch(): Promise<FetchResult> {
            fetched += 1;
            return { ok: false, reason: "fetch_failed" };
          },
        },
        generateKey: async () => makeKey(),
      },
    );
    expect(code).toBe(1);
    expect(out.join("\n")).toContain("key_in_tree");
    expect(fetched).toBe(0);
  });
});
