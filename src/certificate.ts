/**
 * Standing certificates: what an operator is handed instead of money.
 *
 * Decision D-127 took the money out and named what is left: "the non-monetary
 * rewards: a signed standing certificate per operator and per agent key,
 * verifiable offline, and an SVG badge". Decision D-130 says why it is worth
 * holding: standing is an asset, public and named, and a certificate is that
 * asset in a form its owner can carry somewhere else and have checked without
 * asking nomankind anything.
 *
 * Offline is the whole point, so a certificate carries its own position in the
 * log: the sealed position it was cut at and the seq the standing fold covered.
 * A reader with the certificate and the log can recompute the number from
 * `src/standing.ts` at exactly that position and get the same answer, which is
 * Section 9's published formula used as a check rather than as a promise. A
 * certificate is a snapshot and says so: standing moves, and one cut last month
 * says what was true last month.
 *
 * The signature is the read receipt's construction (src/receipt.ts): a
 * domain-separation tag, a newline, and the RFC 8785 canonical JSON of exactly
 * the fields being signed. The tag is what stops a certificate from ever being
 * replayed as a receipt, a record, an entry or a seal, and the issuer is the
 * sealing agent — the same key that signs what the record hands out.
 *
 * Pure: no I/O, no storage, no clock. The caller supplies `issued_at` from the
 * injected clock and every number from the fold. Ed25519 goes through WebCrypto
 * only (src/identity.ts), so this runs unchanged on Cloudflare Workers.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";
import { canonicalize } from "./hash.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";
import type { OperatorKind, Tier } from "./policy.js";
import type { RecordMarks, StandingCounts } from "./standing.js";

/**
 * Domain-separation tag, and the version the document names itself by. A format
 * constant, not a policy number: it names what the signature is over.
 */
export const HASH_TAG_CERTIFICATE = "nomankind-certificate-v1";

/** Who a certificate is about: an operator, or one agent key under one. */
export type CertificateSubject =
  | {
      readonly kind: "operator";
      readonly id: string;
      readonly operator_kind: OperatorKind;
      /**
       * The disclosed perimeter this operator registered under (D-128), or null
       * where it disclosed none. Carried because a certificate is shown to
       * somebody who cannot look the operator up, and the perimeter is the part
       * of an operator's name that is about independence.
       */
      readonly perimeter: string | null;
    }
  | { readonly kind: "agent"; readonly agent: string; readonly operator: string };

/** How many marks of each kind the Record holds; the marks' own lengths. */
export interface CertificateMarks {
  readonly overturned: number;
  readonly missed: number;
  readonly failed_disputes: number;
}

/** The document, exactly as it is signed and served. */
export interface Certificate {
  readonly version: typeof HASH_TAG_CERTIFICATE;
  readonly subject: CertificateSubject;
  readonly standing: number;
  readonly tier: Tier;
  readonly counts: StandingCounts;
  readonly marks: CertificateMarks;
  /** The newest seal's position when the certificate was cut. */
  readonly sealed_position: number;
  /** The log position the standing fold behind these numbers covered. */
  readonly folded_through_seq: number;
  readonly issued_at: string;
  /** The sealing agent's 1F916 id (D-014: an agent id is its public key). */
  readonly issuer: string;
}

/** The certificate and the signature over it, which is what is handed out. */
export interface SignedCertificate {
  readonly certificate: Certificate;
  /** Unpadded base64url, the encoding every other kernel signature uses. */
  readonly signature: string;
}

/** What the caller gathers; the version and the shape are this module's. */
export interface CertificateInput {
  readonly subject: CertificateSubject;
  readonly standing: number;
  readonly tier: Tier;
  readonly counts: StandingCounts;
  readonly marks: RecordMarks | CertificateMarks;
  readonly sealed_position: number;
  readonly folded_through_seq: number;
  readonly issued_at: string;
  readonly issuer: string;
}

const encoder = new TextEncoder();

/** The mark counts, whether the caller handed in the marks or their lengths. */
function markCounts(marks: RecordMarks | CertificateMarks): CertificateMarks {
  if (Array.isArray((marks as RecordMarks).overturned)) {
    const record = marks as RecordMarks;
    return {
      overturned: record.overturned.length,
      missed: record.missed.length,
      failed_disputes: record.failed_disputes.length,
    };
  }
  return marks as CertificateMarks;
}

/**
 * The exact bytes an issuer signs: the tag, a newline, and the canonical JSON
 * of the certificate. The signature is never over itself, so a verifier rebuilds
 * these bytes from the document it holds and asks the key named inside it.
 */
export function certificateSigningBytes(certificate: Certificate): Uint8Array {
  return encoder.encode(
    `${HASH_TAG_CERTIFICATE}\n${canonicalize(certificate)}`,
  );
}

/** Build and sign one certificate. */
export async function buildCertificate(
  input: CertificateInput,
  privateKey: CryptoKey,
): Promise<SignedCertificate> {
  const certificate: Certificate = {
    version: HASH_TAG_CERTIFICATE,
    subject: input.subject,
    standing: input.standing,
    tier: input.tier,
    counts: input.counts,
    marks: markCounts(input.marks),
    sealed_position: input.sealed_position,
    folded_through_seq: input.folded_through_seq,
    issued_at: input.issued_at,
    issuer: input.issuer,
  };
  const signature = await signBytes(
    privateKey,
    certificateSigningBytes(certificate),
  );
  return { certificate, signature: base64urlEncode(signature) };
}

/** Whether a value is a plain object rather than null or an array. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The issuer a signed certificate names, or null when it names none. */
export function certificateIssuer(signed: unknown): string | null {
  if (!isRecord(signed)) return null;
  const certificate = signed["certificate"];
  if (!isRecord(certificate)) return null;
  const issuer = certificate["issuer"];
  return typeof issuer === "string" ? issuer : null;
}

/**
 * Verify a certificate against an issuer's key.
 *
 * `issuerPublicKey` is the agent id the reader expects — the record's own
 * sealing agent, which they compare against the id printed beside the verdict —
 * or absent to check against the id inside the document, which answers "this
 * document is internally consistent" and not "this is nomankind's".
 *
 * Returns false, never throws, on anything malformed: a document that is not an
 * object, an issuer that carries no key, a signature that is not base64url. A
 * stranger's file gets a verdict, not an exception.
 */
export async function verifyCertificate(
  signed: unknown,
  issuerPublicKey?: string,
): Promise<boolean> {
  try {
    if (!isRecord(signed)) return false;
    const certificate = signed["certificate"];
    const signature = signed["signature"];
    if (!isRecord(certificate) || typeof signature !== "string") return false;
    if (certificate["version"] !== HASH_TAG_CERTIFICATE) return false;
    const issuer = certificate["issuer"];
    if (typeof issuer !== "string") return false;
    // A certificate checked against a named issuer that is not the one inside
    // it is not this issuer's certificate, whatever its signature says.
    if (issuerPublicKey !== undefined && issuerPublicKey !== issuer) {
      return false;
    }
    return await verifyBytes(
      publicKeyFromAgentId(issuer),
      certificateSigningBytes(certificate as unknown as Certificate),
      base64urlDecode(signature),
    );
  } catch {
    return false;
  }
}
