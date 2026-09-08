/**
 * The snapshot archive, in R2.
 *
 * Snapshot normalization rule, step 2 (Archive): "Store the raw response body
 * in the content-addressed snapshot archive at `sha256` of the body bytes.
 * Store a sidecar at `<hash>.meta.json` with `{final_url, status, headers,
 * fetched_at, fetcher}` where `fetcher` is the 1F916 identity that fetched. The
 * raw capture is evidence and is never what `snapshot_hash` hashes."
 *
 * So the key is the archive address itself — the string `sha256:<hex>`, exactly
 * as it appears on an entry — and the sidecar sits at that key plus
 * `.meta.json`. An object is therefore immutable by construction: two bodies
 * that hash the same are the same bytes, and a second capture of them is not
 * news. Both writes are made only when the object is absent, so the first
 * capture's sidecar — the one that says when and from where this evidence was
 * taken — is never overwritten by a later fetch of the same page.
 *
 * The interface is structural, as src/storage/d1.ts is for D1: only the three
 * methods this layer calls are declared, so the kernel stays buildable with the
 * approved dependency baseline and a test can hand in any object with them.
 * Nothing here imports a `node:` module or Cloudflare's generated types.
 *
 * A missing object is a value, never a throw: `readCapture` and `readSidecar`
 * answer null. A bucket that does not answer at all is a different thing, and
 * those errors propagate to the route's own boundary, which turns them into a
 * 503 rather than a 500.
 */

/** The bit of R2's httpMetadata this layer sets and reads. */
export interface R2LikeHttpMetadata {
  readonly contentType?: string;
}

/** An object's metadata, without its body. */
export interface R2LikeObject {
  readonly key: string;
  readonly size: number;
  readonly httpMetadata?: R2LikeHttpMetadata;
}

/** An object with its body, as `get` returns it. */
export interface R2LikeObjectBody extends R2LikeObject {
  arrayBuffer(): Promise<ArrayBuffer>;
  text(): Promise<string>;
}

/** What a write may say about the object it stores. */
export interface R2LikePutOptions {
  readonly httpMetadata?: R2LikeHttpMetadata;
}

/** The narrow R2 surface the archive uses. */
export interface R2Like {
  put(
    key: string,
    value: ArrayBuffer | ArrayBufferView | string,
    options?: R2LikePutOptions,
  ): Promise<R2LikeObject | null>;
  get(key: string): Promise<R2LikeObjectBody | null>;
  head(key: string): Promise<R2LikeObject | null>;
}

/**
 * The sidecar the norm rule names, with exactly its five keys.
 *
 * `final_url` and `status` are null for an artifact that was never fetched —
 * the transcript artifact of a behavior entry, an observation receipt — and
 * `headers` is then empty. That is a documented deviation from the rule, which
 * writes the sidecar for a fetched page only: the archive holds both kinds of
 * evidence at the same addresses, and a sidecar saying "nobody fetched this"
 * is a truer record than no sidecar at all.
 */
export interface Sidecar {
  readonly final_url: string | null;
  readonly status: number | null;
  readonly headers: Record<string, string>;
  readonly fetched_at: string;
  readonly fetcher: string;
}

/** The media type a sidecar is stored under. */
const SIDECAR_MEDIA_TYPE = "application/json";

/** The suffix the norm rule gives the sidecar's key. */
export const SIDECAR_SUFFIX = ".meta.json";

/** The sidecar's key for one archive address. */
export function sidecarKey(archiveHash: string): string {
  return `${archiveHash}${SIDECAR_SUFFIX}`;
}

/** One capture on its way into the archive. */
export interface CaptureUpload {
  /** The archive address: `sha256:<hex>` over the raw bytes. */
  readonly archiveHash: string;
  readonly bytes: Uint8Array;
  readonly mediaType: string;
  readonly sidecar: Sidecar;
}

/**
 * Store one capture and its sidecar, each only when it is not there already.
 *
 * The head-then-put is not a lock and does not need to be: the objects are
 * content addressed, so two writers racing on the same address write the same
 * bytes. The check exists for the sidecar, which is not addressed by its own
 * content: the earliest capture's provenance is the one worth keeping.
 */
export async function archiveCapture(
  bucket: R2Like,
  upload: CaptureUpload,
): Promise<void> {
  if ((await bucket.head(upload.archiveHash)) === null) {
    await bucket.put(upload.archiveHash, upload.bytes, {
      httpMetadata: { contentType: upload.mediaType },
    });
  }
  const key = sidecarKey(upload.archiveHash);
  if ((await bucket.head(key)) === null) {
    await bucket.put(key, JSON.stringify(upload.sidecar), {
      httpMetadata: { contentType: SIDECAR_MEDIA_TYPE },
    });
  }
}

/** A stored capture: the bytes as they were fetched, and their media type. */
export interface StoredCapture {
  readonly bytes: Uint8Array;
  readonly mediaType: string | null;
}

/** One capture by its archive address, or null when the archive has none. */
export async function readCapture(
  bucket: R2Like,
  archiveHash: string,
): Promise<StoredCapture | null> {
  const object = await bucket.get(archiveHash);
  if (object === null) return null;
  return {
    bytes: new Uint8Array(await object.arrayBuffer()),
    mediaType: object.httpMetadata?.contentType ?? null,
  };
}

/** One capture's sidecar, or null when the archive has none. */
export async function readSidecar(
  bucket: R2Like,
  archiveHash: string,
): Promise<Sidecar | null> {
  const object = await bucket.get(sidecarKey(archiveHash));
  if (object === null) return null;
  return JSON.parse(await object.text()) as Sidecar;
}
