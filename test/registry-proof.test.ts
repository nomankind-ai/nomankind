/**
 * The founding registry's proof formats, against the registry's own wire.
 *
 * Every vector here is a verbatim response captured from https://1f916.ai
 * (test/fixtures/registry/README.md), not a hand-made tree: the point of this
 * module is that our verifier agrees with theirs, and a fixture we computed
 * ourselves could only prove we agree with ourselves.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { base64urlDecode } from "../src/encoding.js";
import { verifyBytes } from "../src/identity.js";
import {
  REGISTRY_CHECKPOINT_TAG,
  REGISTRY_WITNESS_TAG,
  isHex64,
  registryCheckpointPayload,
  registryLeafHash,
  registryWitnessPayload,
  verifyRegistryConsistency,
  verifyRegistryInclusion,
} from "../src/registry-proof.js";
import {
  consistencyOf,
  leafOf,
  pathOf,
  rootOf,
} from "./helpers/registry-tree.js";

function fixture<T>(name: string): T {
  return JSON.parse(
    readFileSync(new URL(`./fixtures/registry/${name}`, import.meta.url), "utf8"),
  ) as T;
}

function lines<T>(name: string): T[] {
  return readFileSync(new URL(`./fixtures/registry/${name}`, import.meta.url), "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as T);
}

interface Head {
  tree_size: number;
  root: string;
  sig: string;
  created_at: number;
}

interface ProofFixture {
  log: string;
  event: { id: number; hash: string; leaf_index: number };
  checkpoint: Head;
  proof: string[];
}

interface ConsistencyFixture {
  log: string;
  from: Head;
  to: Head;
  proof: string[];
}

interface CheckpointFixture {
  registry_public_key: { x: string };
  checkpoints: Array<Head & { log: string }>;
}

interface WitnessLine {
  registry: string;
  log: string;
  tree_size: number;
  root: string;
  created_at: number;
  registry_sig: string;
  witness_sig: string;
  witness_public_key: string;
}

const PROOF = fixture<ProofFixture>("proof-identity_events-103.json");
const CONSISTENCY = fixture<ConsistencyFixture>(
  "consistency-identity_events-89-9128.json",
);
const CHECKPOINT = fixture<CheckpointFixture>("checkpoint.json");
const WITNESS_LINES = lines<WitnessLine>("witness-lines-liveness.jsonl");

/** The registry's own signing key, as the checkpoint publishes it. */
const REGISTRY_KEY = base64urlDecode(CHECKPOINT.registry_public_key.x);

/** The head the checkpoint fixture publishes for the identity log. */
const IDENTITY_HEAD = CHECKPOINT.checkpoints.find(
  (head) => head.log === "identity_events",
)!;

describe("isHex64", () => {
  it("is exactly 64 lowercase hex characters", () => {
    expect(isHex64(PROOF.event.hash)).toBe(true);
    expect(isHex64(PROOF.event.hash.toUpperCase())).toBe(false);
    expect(isHex64(PROOF.event.hash.slice(1))).toBe(false);
    expect(isHex64(`${PROOF.event.hash}0`)).toBe(false);
    expect(isHex64(`sha256:${PROOF.event.hash}`)).toBe(false);
    expect(isHex64("")).toBe(false);
    expect(isHex64(null)).toBe(false);
    expect(isHex64(89)).toBe(false);
  });
});

describe("registryLeafHash", () => {
  it("hashes the hex text, not the bytes it spells", async () => {
    // The value the orchestrator confirmed against the live registry, and the
    // same hash the 89-to-9128 consistency proof carries as its first node:
    // the leaf at index 88 is a complete subtree of size one.
    expect(await registryLeafHash(PROOF.event.hash)).toBe(
      "00778d318c74e0a9adb2f4053ebe55c4257881eb32a422d21095b3f27bd9a561",
    );
    expect(CONSISTENCY.proof[0]).toBe(await registryLeafHash(PROOF.event.hash));
  });
});

describe("verifyRegistryInclusion", () => {
  const base = async () => ({
    leafHash: await registryLeafHash(PROOF.event.hash),
    leafIndex: PROOF.event.leaf_index,
    treeSize: PROOF.checkpoint.tree_size,
    path: PROOF.proof,
    root: PROOF.checkpoint.root,
  });

  it("verifies event 103 at leaf 88 against the head at tree size 89", async () => {
    expect(PROOF.event.leaf_index).toBe(88);
    expect(PROOF.checkpoint.tree_size).toBe(89);
    expect(PROOF.checkpoint.root).toBe(
      "3798c74b045e09c8f76822d68456f07bbc6a9aab9e4b79bb4a7400342e7ab42e",
    );
    expect(await verifyRegistryInclusion(await base())).toBe(true);
  });

  it("refuses a flipped hex character in the root", async () => {
    const root = `${PROOF.checkpoint.root.slice(0, 63)}${
      PROOF.checkpoint.root.endsWith("e") ? "f" : "e"
    }`;
    expect(await verifyRegistryInclusion({ ...(await base()), root })).toBe(false);
  });

  it("refuses a swapped path element", async () => {
    const path = [...PROOF.proof];
    [path[0], path[1]] = [path[1]!, path[0]!];
    expect(await verifyRegistryInclusion({ ...(await base()), path })).toBe(false);
  });

  it("refuses an index equal to the size", async () => {
    expect(
      await verifyRegistryInclusion({ ...(await base()), leafIndex: 89 }),
    ).toBe(false);
  });

  it("refuses a float, a negative, and an uppercase hash, without throwing", async () => {
    expect(
      await verifyRegistryInclusion({ ...(await base()), leafIndex: 88.5 }),
    ).toBe(false);
    expect(
      await verifyRegistryInclusion({ ...(await base()), leafIndex: -1 }),
    ).toBe(false);
    expect(
      await verifyRegistryInclusion({ ...(await base()), treeSize: -89 }),
    ).toBe(false);
    expect(
      await verifyRegistryInclusion({
        ...(await base()),
        root: PROOF.checkpoint.root.toUpperCase(),
      }),
    ).toBe(false);
    expect(
      await verifyRegistryInclusion({
        ...(await base()),
        leafHash: PROOF.event.hash.toUpperCase(),
      }),
    ).toBe(false);
    expect(
      await verifyRegistryInclusion({
        ...(await base()),
        path: [...PROOF.proof, "not a hash"],
      }),
    ).toBe(false);
    expect(
      await verifyRegistryInclusion(
        undefined as unknown as Parameters<typeof verifyRegistryInclusion>[0],
      ),
    ).toBe(false);
  });

  it("refuses the leaf against another head's root", async () => {
    expect(
      await verifyRegistryInclusion({
        ...(await base()),
        root: CONSISTENCY.to.root,
      }),
    ).toBe(false);
  });
});

describe("verifyRegistryConsistency", () => {
  const base = (): Parameters<typeof verifyRegistryConsistency>[0] => ({
    fromSize: CONSISTENCY.from.tree_size,
    fromRoot: CONSISTENCY.from.root,
    toSize: CONSISTENCY.to.tree_size,
    toRoot: CONSISTENCY.to.root,
    path: CONSISTENCY.proof,
  });

  it("verifies 89 to 9128 on the identity log", async () => {
    expect(CONSISTENCY.from.tree_size).toBe(89);
    expect(CONSISTENCY.to.tree_size).toBe(9128);
    expect(await verifyRegistryConsistency(base())).toBe(true);
  });

  it("refuses a flipped hex character in either root", async () => {
    const flip = (hash: string): string =>
      `${hash.slice(0, 63)}${hash.endsWith("f") ? "e" : "f"}`;
    expect(
      await verifyRegistryConsistency({
        ...base(),
        fromRoot: flip(CONSISTENCY.from.root),
      }),
    ).toBe(false);
    expect(
      await verifyRegistryConsistency({
        ...base(),
        toRoot: flip(CONSISTENCY.to.root),
      }),
    ).toBe(false);
  });

  it("refuses a swapped path element", async () => {
    const path = [...CONSISTENCY.proof];
    [path[2], path[3]] = [path[3]!, path[2]!];
    expect(await verifyRegistryConsistency({ ...base(), path })).toBe(false);
  });

  it("holds the same size to equal roots and an empty path", async () => {
    const root = CONSISTENCY.to.root;
    expect(
      await verifyRegistryConsistency({
        fromSize: 9128,
        fromRoot: root,
        toSize: 9128,
        toRoot: root,
        path: [],
      }),
    ).toBe(true);
    expect(
      await verifyRegistryConsistency({
        fromSize: 9128,
        fromRoot: root,
        toSize: 9128,
        toRoot: root,
        path: [CONSISTENCY.proof[0]!],
      }),
    ).toBe(false);
    expect(
      await verifyRegistryConsistency({
        fromSize: 9128,
        fromRoot: CONSISTENCY.from.root,
        toSize: 9128,
        toRoot: root,
        path: [],
      }),
    ).toBe(false);
  });

  it("holds an empty tree only against an empty path", async () => {
    expect(
      await verifyRegistryConsistency({ ...base(), fromSize: 0, path: [] }),
    ).toBe(true);
    expect(await verifyRegistryConsistency({ ...base(), fromSize: 0 })).toBe(false);
  });

  it("refuses a shrinking log, a float and a negative, without throwing", async () => {
    expect(
      await verifyRegistryConsistency({ ...base(), fromSize: 9200 }),
    ).toBe(false);
    expect(await verifyRegistryConsistency({ ...base(), fromSize: 89.5 })).toBe(
      false,
    );
    expect(await verifyRegistryConsistency({ ...base(), toSize: -9128 })).toBe(
      false,
    );
    expect(
      await verifyRegistryConsistency({
        ...base(),
        toRoot: CONSISTENCY.to.root.toUpperCase(),
      }),
    ).toBe(false);
    expect(
      await verifyRegistryConsistency(
        undefined as unknown as Parameters<typeof verifyRegistryConsistency>[0],
      ),
    ).toBe(false);
  });
});

describe("registryCheckpointPayload", () => {
  it("is the registry's published format", () => {
    expect(REGISTRY_CHECKPOINT_TAG).toBe("1f916.checkpoint.v1");
    expect(
      new TextDecoder().decode(
        registryCheckpointPayload({
          log: "identity_events",
          tree_size: 89,
          root: PROOF.checkpoint.root,
          created_at: PROOF.checkpoint.created_at,
        }),
      ),
    ).toBe(
      `1f916.checkpoint.v1:identity_events:89:${PROOF.checkpoint.root}:${PROOF.checkpoint.created_at}`,
    );
  });

  it("verifies the identity head under the registry's own key", async () => {
    expect(
      await verifyBytes(
        REGISTRY_KEY,
        registryCheckpointPayload({
          log: IDENTITY_HEAD.log,
          tree_size: IDENTITY_HEAD.tree_size,
          root: IDENTITY_HEAD.root,
          created_at: IDENTITY_HEAD.created_at,
        }),
        base64urlDecode(IDENTITY_HEAD.sig),
      ),
    ).toBe(true);
  });

  it("verifies the two heads the proof fixtures carry", async () => {
    for (const head of [CONSISTENCY.from, CONSISTENCY.to]) {
      expect(
        await verifyBytes(
          REGISTRY_KEY,
          registryCheckpointPayload({
            log: CONSISTENCY.log,
            tree_size: head.tree_size,
            root: head.root,
            created_at: head.created_at,
          }),
          base64urlDecode(head.sig),
        ),
      ).toBe(true);
    }
  });

  it("refuses the head under a changed tree size", async () => {
    expect(
      await verifyBytes(
        REGISTRY_KEY,
        registryCheckpointPayload({
          log: IDENTITY_HEAD.log,
          tree_size: IDENTITY_HEAD.tree_size + 1,
          root: IDENTITY_HEAD.root,
          created_at: IDENTITY_HEAD.created_at,
        }),
        base64urlDecode(IDENTITY_HEAD.sig),
      ),
    ).toBe(false);
  });
});

describe("registryWitnessPayload", () => {
  it("is the registry's published format, without the clock", () => {
    expect(REGISTRY_WITNESS_TAG).toBe("1f916.witness.v1");
    expect(
      new TextDecoder().decode(
        registryWitnessPayload({
          registry: "https://1f916.ai",
          log: "identity_events",
          tree_size: 9125,
          root: WITNESS_LINES[1]!.root,
        }),
      ),
    ).toBe(`1f916.witness.v1:https://1f916.ai:identity_events:9125:${WITNESS_LINES[1]!.root}`);
  });

  it("verifies every captured liveness countersignature", async () => {
    expect(WITNESS_LINES.length).toBeGreaterThan(0);
    for (const line of WITNESS_LINES) {
      expect(line.witness_public_key).toBe(
        "NgHCVDwGuYeHX0qnuOKBgufNwgu804x1ZDyTU63sJwE",
      );
      expect(
        await verifyBytes(
          base64urlDecode(line.witness_public_key),
          registryWitnessPayload({
            registry: line.registry,
            log: line.log,
            tree_size: line.tree_size,
            root: line.root,
          }),
          base64urlDecode(line.witness_sig),
        ),
      ).toBe(true);
      // And the head that line countersigns is the registry's own.
      expect(
        await verifyBytes(
          REGISTRY_KEY,
          registryCheckpointPayload({
            log: line.log,
            tree_size: line.tree_size,
            root: line.root,
            created_at: line.created_at,
          }),
          base64urlDecode(line.registry_sig),
        ),
      ).toBe(true);
    }
  });

  it("refuses a countersignature read against another registry origin", async () => {
    const line = WITNESS_LINES[0]!;
    expect(
      await verifyBytes(
        base64urlDecode(line.witness_public_key),
        registryWitnessPayload({
          registry: "https://not-1f916.example",
          log: line.log,
          tree_size: line.tree_size,
          root: line.root,
        }),
        base64urlDecode(line.witness_sig),
      ),
    ).toBe(false);
  });
});

/**
 * The fixtures pin the verifier to the real registry at two sizes. This pins it
 * at every size up to twenty, against a generator written from the RFC's own
 * recursions rather than from the verifier's fold (test/helpers/registry-tree.ts)
 * — including the odd sizes where the right-hand subtree is incomplete, which is
 * where a fold that trusts a direction flag goes wrong.
 */
describe("against an independent RFC 6962 generator", () => {
  it("verifies every leaf of every tree up to twenty", async () => {
    const leaves: string[] = [];
    for (let index = 0; index < 20; index += 1) {
      leaves.push(await leafOf(`nmk-leaf-${index}`));
    }

    for (let size = 1; size <= leaves.length; size += 1) {
      const tree = leaves.slice(0, size);
      const root = await rootOf(tree);
      for (let index = 0; index < size; index += 1) {
        expect(
          await verifyRegistryInclusion({
            leafHash: tree[index]!,
            leafIndex: index,
            treeSize: size,
            path: await pathOf(tree, index),
            root,
          }),
        ).toBe(true);
      }
      // And a leaf that is in the tree at the wrong index is refused.
      if (size > 1) {
        expect(
          await verifyRegistryInclusion({
            leafHash: tree[0]!,
            leafIndex: size - 1,
            treeSize: size,
            path: await pathOf(tree, 0),
            root,
          }),
        ).toBe(false);
      }
    }
  });

  it("bridges every earlier head to every later one", async () => {
    const leaves: string[] = [];
    for (let index = 0; index < 20; index += 1) {
      leaves.push(await leafOf(`nmk-leaf-${index}`));
    }

    for (let toSize = 1; toSize <= leaves.length; toSize += 1) {
      const tree = leaves.slice(0, toSize);
      const toRoot = await rootOf(tree);
      for (let fromSize = 1; fromSize <= toSize; fromSize += 1) {
        const fromRoot = await rootOf(tree.slice(0, fromSize));
        const path = await consistencyOf(tree, fromSize);
        expect(
          await verifyRegistryConsistency({
            fromSize,
            fromRoot,
            toSize,
            toRoot,
            path,
          }),
        ).toBe(true);
        // The same proof against a root the log never had is refused. A
        // flipped character rather than another leaf's hash: at size one the
        // root *is* the leaf, so "another leaf" would sometimes be right.
        if (fromSize < toSize) {
          expect(
            await verifyRegistryConsistency({
              fromSize,
              fromRoot: `${fromRoot.slice(0, 63)}${fromRoot.endsWith("f") ? "e" : "f"}`,
              toSize,
              toRoot,
              path,
            }),
          ).toBe(false);
        }
      }
    }
  });
});
