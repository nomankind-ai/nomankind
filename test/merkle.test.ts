/**
 * The Merkle tree and its inclusion proofs.
 *
 * Whitepaper Section 6, "Seal": "anyone can verify offline that an entry or
 * event existed and has not changed". These tests are that verifier's side of
 * the bargain — a proof that verifies, and every way of tampering with one that
 * must not.
 *
 * The root digests below are pinned as literals on purpose. They were computed
 * once from this construction and pasted; if the tags, the separator, or the
 * tree shape ever change, these fail rather than silently redefining what an
 * older proof meant.
 */

import { describe, expect, it } from "vitest";

import {
  HASH_TAG_MERKLE_LEAF,
  HASH_TAG_MERKLE_NODE,
  decodeProof,
  encodeProof,
  inclusionProof,
  merkleRoot,
  verifyInclusion,
  type InclusionProof,
} from "../src/merkle.js";

const leaf = (index: number): string => `leaf-${index}`;

const leaves = (size: number): string[] =>
  Array.from({ length: size }, (_, index) => leaf(index));

/** Known answers for sizes 0 through 9, computed once from this construction. */
const PINNED_ROOTS: readonly string[] = [
  "sha256:2cc210a6b6e14665c5e03d03e82c298a5b5cceb6541d694452f594a03c335e93",
  "sha256:d5c6102d1dd9d556bbc178b39cd8dd7373f163c7f307fdc39588eb22d666a2c9",
  "sha256:7c9090802fadd78d3f534490e3ded7356f528d154fc6a7fff9f278a29eb396ff",
  "sha256:551ae0c110c02e053f348b11c658839d5994b73a841399d526d23051eda75186",
  "sha256:2708e647de4647e42787f2d18605c4a967c67c2efc4674f0f36cf628acbb675c",
  "sha256:adbea609151ac249c77b7ede2c38a09ba16d503b142a67b1ef427d6df4dc03a1",
  "sha256:502a00694891d3df98845d4d48d4c6f794a742e2dca3c4b9c0c73746a184a9cb",
  "sha256:1e09410ba96d1c53b0335bbe90bd3d6a7efac2f2b74b47566d8387a3f0ae4e8f",
  "sha256:b08a1637b94fa6941347c31e8133df65c00c5058e79366b2760f5caeb56c2ea1",
  "sha256:a8f7407181e26fc1fae97a3355a1d2fb33a5d093596211f58d0a87fe4455f75e",
];

describe("merkleRoot", () => {
  it("names its hash construction, so a proof cannot be replayed across kinds", () => {
    expect(HASH_TAG_MERKLE_LEAF).toBe("nomankind-merkle-leaf-v1");
    expect(HASH_TAG_MERKLE_NODE).toBe("nomankind-merkle-node-v1");
    expect(HASH_TAG_MERKLE_LEAF).not.toBe(HASH_TAG_MERKLE_NODE);
  });

  it("is deterministic and pinned for sizes 0 through 9", async () => {
    for (let size = 0; size < PINNED_ROOTS.length; size += 1) {
      const root = await merkleRoot(leaves(size));
      expect(root).toBe(PINNED_ROOTS[size]);
      expect(root).toMatch(/^sha256:[0-9a-f]{64}$/);
      // Same leaves, same answer, every time.
      expect(await merkleRoot(leaves(size))).toBe(root);
    }
    // No two sizes collide: the empty tree has a root of its own.
    expect(new Set(PINNED_ROOTS).size).toBe(PINNED_ROOTS.length);
  });

  it("depends on leaf order, so a reordered batch is a different batch", async () => {
    const forward = await merkleRoot(["a", "b", "c"]);
    const reversed = await merkleRoot(["c", "b", "a"]);
    expect(forward).not.toBe(reversed);
  });
});

describe("inclusionProof and verifyInclusion", () => {
  it("verifies every index of every size from 1 to 17", async () => {
    for (let size = 1; size <= 17; size += 1) {
      const batch = leaves(size);
      const root = await merkleRoot(batch);
      for (let index = 0; index < size; index += 1) {
        const proof = await inclusionProof(batch, index);
        expect(proof.index).toBe(index);
        expect(proof.size).toBe(size);
        expect(await verifyInclusion(batch[index]!, proof, root)).toBe(true);
      }
    }
  });

  it("throws RangeError for an index outside the tree", async () => {
    await expect(inclusionProof(leaves(4), 4)).rejects.toBeInstanceOf(RangeError);
    await expect(inclusionProof(leaves(4), -1)).rejects.toBeInstanceOf(RangeError);
    await expect(inclusionProof([], 0)).rejects.toBeInstanceOf(RangeError);
  });

  it("refuses a flipped leaf, a wrong index, a wrong root, and a truncated path", async () => {
    const batch = leaves(9);
    const root = await merkleRoot(batch);
    const proof = await inclusionProof(batch, 5);

    // The proof is good to begin with.
    expect(await verifyInclusion(batch[5]!, proof, root)).toBe(true);

    // A different leaf under the same proof.
    expect(await verifyInclusion("flipped", proof, root)).toBe(false);

    // The right leaf claimed at the wrong position.
    expect(await verifyInclusion(batch[5]!, { ...proof, index: 4 }, root)).toBe(
      false,
    );
    expect(
      await verifyInclusion(batch[5]!, { ...proof, index: 9 }, root),
    ).toBe(false);

    // The right proof against somebody else's root.
    expect(
      await verifyInclusion(batch[5]!, proof, await merkleRoot(leaves(8))),
    ).toBe(false);

    // A path one hash short, and one hash too long.
    expect(
      await verifyInclusion(
        batch[5]!,
        { ...proof, path: proof.path.slice(0, -1) },
        root,
      ),
    ).toBe(false);
    expect(
      await verifyInclusion(
        batch[5]!,
        { ...proof, path: [...proof.path, proof.path[0]!] },
        root,
      ),
    ).toBe(false);
  });

  it("returns false rather than throwing on a malformed proof", async () => {
    const batch = leaves(5);
    const root = await merkleRoot(batch);
    const malformed: readonly unknown[] = [
      { index: -1, size: 5, path: [] },
      { index: 1.5, size: 5, path: [] },
      { index: 0, size: 0, path: [] },
      { index: 0, size: 5, path: "not-an-array" },
      { index: 0, size: 5, path: [42] },
      { index: 0, path: [] },
      null,
      "nonsense",
    ];
    for (const proof of malformed) {
      expect(
        await verifyInclusion(batch[0]!, proof as InclusionProof, root),
      ).toBe(false);
    }
  });
});

describe("encodeProof and decodeProof", () => {
  it("round-trips a proof through the string the seal carries", async () => {
    const batch = leaves(11);
    const root = await merkleRoot(batch);
    for (let index = 0; index < batch.length; index += 1) {
      const proof = await inclusionProof(batch, index);
      const encoded = encodeProof(proof);
      const decoded = decodeProof(encoded);
      expect(decoded).toEqual(proof);
      expect(await verifyInclusion(batch[index]!, decoded!, root)).toBe(true);
      // Canonical: the same proof is always the same bytes.
      expect(encodeProof(decoded!)).toBe(encoded);
    }
  });

  it("rejects garbage and anything that is not exactly the shape", () => {
    const garbage: readonly string[] = [
      "",
      "not json",
      "[]",
      "null",
      "42",
      '{"index":0,"size":4}',
      '{"index":0,"size":4,"path":"nope"}',
      '{"index":0,"size":4,"path":[1,2]}',
      '{"index":-1,"size":4,"path":[]}',
      '{"index":4,"size":4,"path":[]}',
      '{"index":0,"size":-4,"path":[]}',
      '{"index":0.5,"size":4,"path":[]}',
    ];
    for (const text of garbage) {
      expect(decodeProof(text)).toBeNull();
    }
  });

  it("refuses a decoded proof with a negative index", async () => {
    const batch = leaves(6);
    const root = await merkleRoot(batch);
    const proof = await inclusionProof(batch, 3);
    const negative = encodeProof({ ...proof, index: -1 });

    // It never decodes at all ...
    expect(decodeProof(negative)).toBeNull();
    // ... and forced past the decoder it still verifies false.
    expect(
      await verifyInclusion(batch[3]!, { ...proof, index: -1 }, root),
    ).toBe(false);
  });
});
