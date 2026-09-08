import { concat, equal, sha256, utf8 } from './bytes.js';

/**
 * The per-minute Merkle tree, RFC 6962 shaped: a leaf is
 * SHA-256(0x00 || id || core_hash), an interior node SHA-256(0x01 || left || right),
 * and a tree of n leaves splits at the largest power of two smaller than n.
 * Inclusion proofs are verified with the algorithm of RFC 9162 section
 * 2.1.3.2, which needs the leaf index and the tree size because the tree is
 * not complete and the side of a proof node cannot be read from the index
 * alone.
 */

export async function leafHash(id: string, coreHash: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x00]), utf8(id), coreHash));
}

export async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

/** The root of a list of leaf hashes (Merkle Tree Hash of RFC 6962 section 2.1). */
export async function treeRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  if (leaves.length === 1) return leaves[0]!;
  const k = largestPowerOfTwoBelow(leaves.length);
  return nodeHash(await treeRoot(leaves.slice(0, k)), await treeRoot(leaves.slice(k)));
}

/** The audit path for leaf `m` of `leaves` (RFC 6962 section 2.1.1). */
export async function inclusionProof(leaves: Uint8Array[], m: number): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (n <= 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) return [...(await inclusionProof(leaves.slice(0, k), m)), await treeRoot(leaves.slice(k))];
  return [...(await inclusionProof(leaves.slice(k), m - k)), await treeRoot(leaves.slice(0, k))];
}

/** RFC 9162 section 2.1.3.2. */
export async function verifyInclusion(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[], root: Uint8Array): Promise<boolean> {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = fn >>> 1;
        sn = sn >>> 1;
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = fn >>> 1;
    sn = sn >>> 1;
  }
  return sn === 0 && equal(r, root);
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
