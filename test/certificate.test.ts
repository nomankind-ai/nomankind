/**
 * The standing certificate: what an operator is handed instead of money.
 *
 * Decision D-127: "the non-monetary rewards: a signed standing certificate per
 * operator and per agent key, verifiable offline, and an SVG badge". Offline is
 * the claim under test here — the document, the key inside its own issuer id,
 * and nothing else — so every case below runs on the pure module and the CLI,
 * with no Worker, no database and no clock but the one handed in.
 *
 * Four things: a certificate verifies; a doctored field does not, whichever
 * field was doctored; a certificate checked against an issuer that did not sign
 * it does not, even though its own signature is sound; and the command exits 0
 * and 1 in exactly those two cases.
 */

import { describe, expect, it } from "vitest";

import {
  buildCertificate,
  certificateIssuer,
  verifyCertificate,
  HASH_TAG_CERTIFICATE,
  type CertificateInput,
} from "../src/certificate.js";
import { verifyCertificateFile, certificatePlan } from "../src/cli/verify.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { STANDING_SENIOR } from "../src/policy.js";
import type { StandingCounts } from "../src/standing.js";
import { verifySignedCertificate } from "../src/verify.js";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ISSUED_AT = "2026-09-17T12:00:00.000Z";

const COUNTS: StandingCounts = {
  validations_volunteered: 4,
  validations_assigned: 2,
  validations_reproduced: 1,
  attestations_scored: 0,
  submissions_verified: 3,
  disputes_upheld: 1,
  revalidations_changed: 0,
  overturned: 1,
  missed: 0,
  forfeits: 1,
};

/** One issuer: a real Ed25519 keypair, and the 1F916 id of its public half. */
async function issuer(): Promise<{ key: CryptoKey; id: string }> {
  const pair = await generateKeypair();
  const id = agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey));
  return { key: pair.privateKey, id };
}

function inputFor(id: string): CertificateInput {
  return {
    subject: {
      kind: "operator",
      id: "k1.example",
      operator_kind: "domain",
      perimeter: null,
    },
    standing: STANDING_SENIOR,
    tier: "senior",
    counts: COUNTS,
    marks: { overturned: 1, missed: 0, failed_disputes: 1 },
    sealed_position: 42,
    folded_through_seq: 42,
    issued_at: ISSUED_AT,
    issuer: id,
  };
}

/** A file in a fresh temporary directory, and its path. */
async function fileWith(value: unknown): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "nmk-certificate-"));
  const path = join(directory, "certificate.json");
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}

/** What the CLI printed, and what it exited with. */
function recorder(): {
  io: { stdout: (line: string) => void; stderr: (line: string) => void };
  out: string[];
  err: string[];
} {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (line) => out.push(line), stderr: (line) => err.push(line) },
    out,
    err,
  };
}

describe("a signed certificate", () => {
  it("carries the numbers it was cut from, and verifies against its issuer", async () => {
    const signing = await issuer();
    const signed = await buildCertificate(inputFor(signing.id), signing.key);

    expect(signed.certificate.version).toBe(HASH_TAG_CERTIFICATE);
    expect(signed.certificate.standing).toBe(STANDING_SENIOR);
    expect(signed.certificate.tier).toBe("senior");
    expect(signed.certificate.counts).toEqual(COUNTS);
    // The position is in the document, which is what makes it checkable: fold
    // the log to this seq and the same number must come back.
    expect(signed.certificate.sealed_position).toBe(42);
    expect(signed.certificate.folded_through_seq).toBe(42);
    expect(signed.certificate.issued_at).toBe(ISSUED_AT);
    expect(certificateIssuer(signed)).toBe(signing.id);

    expect(await verifyCertificate(signed)).toBe(true);
    expect(await verifyCertificate(signed, signing.id)).toBe(true);
  });

  it("counts the marks when it is handed the marks themselves", async () => {
    const signing = await issuer();
    const signed = await buildCertificate(
      {
        ...inputFor(signing.id),
        marks: {
          overturned: [
            {
              entry_id: "entry-1",
              role: "validator",
              agent: "1F916:k1",
              seq: 7,
              at: ISSUED_AT,
              correction_entry_id: "correction-1",
            },
          ],
          missed: [],
          failed_disputes: [
            { correction_entry_id: "correction-2", seq: 9, at: ISSUED_AT },
          ],
        },
      },
      signing.key,
    );
    // A certificate carries the tally and not the rows: the rows are the
    // Record's own page, derived from the events every time it is read, and a
    // document that copied them would be a second place they live.
    expect(signed.certificate.marks).toEqual({
      overturned: 1,
      missed: 0,
      failed_disputes: 1,
    });
    expect(await verifyCertificate(signed)).toBe(true);
  });

  it("refuses a doctored field, whichever field was doctored", async () => {
    const signing = await issuer();
    const signed = await buildCertificate(inputFor(signing.id), signing.key);

    for (const doctored of [
      { ...signed.certificate, standing: STANDING_SENIOR + 1 },
      { ...signed.certificate, tier: "established" as const },
      { ...signed.certificate, sealed_position: 43 },
      // The position the numbers were folded to: a certificate re-pointed at a
      // later fold would claim its numbers are newer than they are.
      { ...signed.certificate, folded_through_seq: 43 },
      { ...signed.certificate, issued_at: "2026-09-18T12:00:00.000Z" },
      {
        ...signed.certificate,
        marks: { overturned: 0, missed: 0, failed_disputes: 0 },
      },
      // The subject, which is the replay this stops: one operator's document
      // renamed to another operator, or to one of its agents, is a signature
      // over somebody else's standing.
      {
        ...signed.certificate,
        subject: {
          kind: "operator" as const,
          id: "k2.example",
          operator_kind: "domain" as const,
          perimeter: null,
        },
      },
      {
        ...signed.certificate,
        subject: {
          kind: "agent" as const,
          agent: "1F916:k1-agent",
          operator: "k1.example",
        },
      },
      {
        ...signed.certificate,
        counts: { ...COUNTS, submissions_verified: 99 },
      },
    ]) {
      expect(
        await verifyCertificate({ ...signed, certificate: doctored }),
      ).toBe(false);
    }

    // And a document that is not one at all.
    expect(await verifyCertificate(null)).toBe(false);
    expect(await verifyCertificate({ certificate: {}, signature: "!" })).toBe(
      false,
    );
  });

  it("refuses a certificate the named issuer did not sign", async () => {
    const signing = await issuer();
    const stranger = await issuer();
    const signed = await buildCertificate(inputFor(signing.id), signing.key);

    // The signature is sound and the document is whole: what fails is that the
    // reader asked for nomankind's sealing agent and got somebody else's.
    expect(await verifyCertificate(signed)).toBe(true);
    expect(await verifyCertificate(signed, stranger.id)).toBe(false);

    const report = await verifySignedCertificate(signed, stranger.id);
    expect([report.ok, report.reason]).toEqual([false, "issuer_mismatch"]);
    expect(report.issuer).toBe(signing.id);
  });

  it("refuses a document signed by a key that is not the one it names", async () => {
    const signing = await issuer();
    const stranger = await issuer();
    // Signed by the stranger, issued in the first agent's name.
    const forged = await buildCertificate(inputFor(signing.id), stranger.key);
    expect(await verifyCertificate(forged)).toBe(false);
  });
});

describe("npm run verify -- --certificate", () => {
  it("reads the flags, and refuses what is not an invocation", () => {
    expect(certificatePlan(["--certificate", "one.json"])).toEqual({
      certificatePath: "one.json",
      issuer: null,
    });
    expect(
      certificatePlan(["--certificate", "one.json", "--issuer", "1F916:x"]),
    ).toEqual({ certificatePath: "one.json", issuer: "1F916:x" });

    for (const args of [
      [],
      ["--certificate"],
      ["--certificate", "--issuer"],
      ["--certificate", "one.json", "--issuer"],
      ["--certificate", "one.json", "--unknown", "x"],
      ["one.json"],
    ]) {
      expect(certificatePlan(args)).toBeNull();
    }
  });

  it("exits 0 on a certificate that verifies, and prints its issuer", async () => {
    const signing = await issuer();
    const signed = await buildCertificate(inputFor(signing.id), signing.key);
    const path = await fileWith(signed);

    const io = recorder();
    expect(await verifyCertificateFile(path, null, io.io)).toBe(0);
    // The issuer is printed whether or not it was given: it is the line the
    // reader compares against the record's own sealing agent.
    expect(io.out).toContain(`issuer ${signing.id}`);
    expect(io.out).toContain("ok certificate");

    const named = recorder();
    expect(await verifyCertificateFile(path, signing.id, named.io)).toBe(0);
  });

  it("exits 1 on a doctored file, a wrong issuer, and a file it cannot read", async () => {
    const signing = await issuer();
    const stranger = await issuer();
    const signed = await buildCertificate(inputFor(signing.id), signing.key);

    const doctored = await fileWith({
      ...signed,
      certificate: { ...signed.certificate, standing: 9_999 },
    });
    const one = recorder();
    expect(await verifyCertificateFile(doctored, null, one.io)).toBe(1);
    expect(one.out).toContain("certificate bad_signature");

    const path = await fileWith(signed);
    const two = recorder();
    expect(await verifyCertificateFile(path, stranger.id, two.io)).toBe(1);
    expect(two.out).toContain("certificate issuer_mismatch");

    const three = recorder();
    expect(
      await verifyCertificateFile(join(tmpdir(), "nmk-no-such.json"), null, three.io),
    ).toBe(1);
    expect(three.err.length).toBe(1);

    // A stranger's file is data: unparsable is a line on stderr, never a throw.
    const directory = await mkdtemp(join(tmpdir(), "nmk-certificate-"));
    const broken = join(directory, "broken.json");
    await writeFile(broken, "{not json", "utf8");
    const four = recorder();
    expect(await verifyCertificateFile(broken, null, four.io)).toBe(1);
  });
});

describe("the agent's own certificate", () => {
  it("names the key and the operator it answers for", async () => {
    const signing = await issuer();
    const signed = await buildCertificate(
      {
        ...inputFor(signing.id),
        subject: {
          kind: "agent",
          agent: "1F916:k1-agent",
          operator: "k1.example",
        },
      },
      signing.key,
    );
    expect(signed.certificate.subject).toEqual({
      kind: "agent",
      agent: "1F916:k1-agent",
      operator: "k1.example",
    });
    expect(await verifyCertificate(signed, signing.id)).toBe(true);

    const report = await verifySignedCertificate(signed);
    expect([report.ok, report.subject]).toEqual([
      true,
      "1F916:k1-agent (k1.example)",
    ]);
  });
});
